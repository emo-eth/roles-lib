// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Role, Roles } from "../src/Roles.sol";
import { RolesExample } from "../src/RolesExample.sol";
import { Test } from "forge-std/Test.sol";

contract RolesExampleTest is Test {

    RolesExample roles;
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");

    function setUp() public {
        roles = new RolesExample();
    }

    function test_immutableRolesAreSetCorrectly() public {
        // First verify individual roles are set correctly
        assertEq(Role.unwrap(roles.ADMIN()), 1 << 0, "ADMIN role should be 2^0");
        assertEq(Role.unwrap(roles.MINTER()), 1 << 1, "MINTER role should be 2^1");
        assertEq(Role.unwrap(roles.PAUSER()), 1 << 2, "PAUSER role should be 2^2");

        // Verify combined roles are set correctly
        assertEq(
            Role.unwrap(roles.ADMIN_OR_MINTER()),
            Role.unwrap(roles.ADMIN()) | Role.unwrap(roles.MINTER()),
            "ADMIN_OR_MINTER should be ADMIN | MINTER"
        );
        assertEq(
            Role.unwrap(roles.EMERGENCY_ROLES()),
            Role.unwrap(roles.ADMIN()) | Role.unwrap(roles.PAUSER()),
            "EMERGENCY_ROLES should be ADMIN | PAUSER"
        );
    }

    function test_deployerHasAdminRole() public {
        assertTrue(roles.hasRoles(address(this), roles.ADMIN()), "Deployer should have ADMIN role");
    }

    function test_adminOrMinterFunction() public {
        // Should fail without role
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.adminOrMinterFunction();

        // Should work with ADMIN role
        roles.adminOrMinterFunction();

        // Should work with MINTER role
        roles.updateRole(bob, roles.MINTER(), true);
        vm.prank(bob);
        roles.adminOrMinterFunction();
    }

    function test_exclusiveRoleCheck() public {
        // Should fail without any roles
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.exclusiveRoleCheck();

        roles.updateRole(alice, roles.TREASURER(), true);
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.exclusiveRoleCheck();

        roles.updateRole(alice, roles.MINTER(), true);
        vm.prank(alice);
        roles.exclusiveRoleCheck();
    }

    function test_complexRoleCheck() public {
        // Should fail without any roles
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.complexRoleCheck();

        roles.updateRole(alice, roles.TREASURER(), true);
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.complexRoleCheck();

        // Should work with TREASURER + ADMIN
        roles.updateRole(bob, roles.TREASURER(), true);
        roles.updateRole(bob, roles.ADMIN(), true);
        vm.prank(bob);
        roles.complexRoleCheck();

        roles.updateRole(alice, roles.MINTER(), true);
        vm.prank(alice);
        roles.complexRoleCheck();
    }

    function test_mintWithPrivilegeCheck() public {
        // Small amount (<=100e18) requires ADMIN or MINTER
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.mintWithPrivilegeCheck(50e18);

        roles.updateRole(alice, roles.MINTER(), true);
        vm.prank(alice);
        roles.mintWithPrivilegeCheck(50e18);

        // Medium amount (>100e18, <=1000e18) requires ADMIN or TREASURER
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.mintWithPrivilegeCheck(500e18);

        roles.updateRole(alice, roles.TREASURER(), true);
        vm.prank(alice);
        roles.mintWithPrivilegeCheck(500e18);

        // Large amount (>1000e18) requires ADMIN
        vm.prank(alice);
        vm.expectRevert(Roles.NotAllowed.selector);
        roles.mintWithPrivilegeCheck(2000e18);

        roles.updateRole(alice, roles.ADMIN(), true);
        vm.prank(alice);
        roles.mintWithPrivilegeCheck(2000e18);
    }

    function test_batchUpdateRole() public {
        address[] memory accounts = new address[](3);
        accounts[0] = alice;
        accounts[1] = bob;
        accounts[2] = makeAddr("charlie");

        // Batch grant MINTER role
        roles.batchUpdateRole(accounts, roles.MINTER(), true);

        // Verify all accounts got the role
        for (uint256 i = 0; i < accounts.length; i++) {
            assertTrue(
                roles.hasRoles(accounts[i], roles.MINTER()), "Account should have MINTER role"
            );
        }

        // Batch revoke MINTER role
        roles.batchUpdateRole(accounts, roles.MINTER(), false);

        // Verify all accounts lost the role
        for (uint256 i = 0; i < accounts.length; i++) {
            assertFalse(
                roles.hasRoles(accounts[i], roles.MINTER()), "Account should not have MINTER role"
            );
        }
    }

}
