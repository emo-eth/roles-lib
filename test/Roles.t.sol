// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Role, Roles, RolesStorage } from "../src/Roles.sol";
import { Test } from "forge-std/Test.sol";

contract RolesTest is Test {

    using Roles for Role;

    // Test accounts
    address ADMIN = makeAddr("ADMIN");
    address USER = makeAddr("USER");
    address OTHER = makeAddr("OTHER");

    // Test roles
    Role immutable ADMIN_ROLE = Roles.role(0);
    Role immutable USER_ROLE = Roles.role(1);
    Role immutable OTHER_ROLE = Roles.role(2);

    function setUp() public {
        // Pre-assign some roles for testing
        Roles.add(ADMIN, ADMIN_ROLE);
        Roles.add(USER, USER_ROLE);
        Roles.add(OTHER, OTHER_ROLE);
    }

    function test_role_Creation() public pure {
        // Test role creation with different IDs
        assertEq(Role.unwrap(Roles.role(0)), 1); // 2^0
        assertEq(Role.unwrap(Roles.role(1)), 2); // 2^1
        assertEq(Role.unwrap(Roles.role(2)), 4); // 2^2
        assertEq(Role.unwrap(Roles.role(8)), 256); // 2^8
    }

    function test_add_EmitsEvent() public {
        address target = makeAddr("TARGET");

        vm.expectEmit(true, true, false, true);
        emit Roles.RoleGranted(target, USER_ROLE);
        Roles.add(target, USER_ROLE);
    }

    function test_remove_EmitsEvent() public {
        address target = makeAddr("TARGET");
        Roles.add(target, USER_ROLE);

        vm.expectEmit(true, true, false, true);
        emit Roles.RoleRevoked(target, USER_ROLE);
        Roles.remove(target, USER_ROLE);
    }

    function test_hasRoles_WithMultipleRoles() public {
        address target = makeAddr("TARGET");

        // Grant multiple roles
        Roles.add(target, USER_ROLE);
        Roles.add(target, OTHER_ROLE);

        // Check individual roles
        assertTrue(Roles.hasRoles(target, USER_ROLE));
        assertTrue(Roles.hasRoles(target, OTHER_ROLE));

        // Check combined roles using getRoles
        uint256 userRoles = Roles.getRoles(target);
        assertEq(userRoles, Role.unwrap(USER_ROLE) | Role.unwrap(OTHER_ROLE));
    }

    function test_combine_CombinesRoles() public {
        address target = makeAddr("TARGET");

        // Test combining roles
        Role combinedRole = Roles.combine(USER_ROLE, OTHER_ROLE);

        // Grant combined role
        Roles.add(target, combinedRole);

        // Verify both roles are present
        assertTrue(Roles.hasRoles(target, USER_ROLE));
        assertTrue(Roles.hasRoles(target, OTHER_ROLE));
    }

    function test_auth_Success() public view {
        // Test successful authorization
        Roles.authAny(USER, USER_ROLE); // Should not revert
    }

    function test_auth_fail_NotAllowed() public {
        address target = makeAddr("TARGET");

        // Test failed authorization
        vm.expectRevert(Roles.NotAllowed.selector);
        this.authAny(target, USER_ROLE);
    }

    function authAny(address target, Role role) external view {
        Roles.authAny(target, role);
    }

    function test_update_AddsAndRemovesRole() public {
        address target = makeAddr("TARGET");

        // Test adding role via update
        Roles.update(target, USER_ROLE, true);
        assertTrue(Roles.hasRoles(target, USER_ROLE));

        // Test removing role via update
        Roles.update(target, USER_ROLE, false);
        assertFalse(Roles.hasRoles(target, USER_ROLE));
    }

    function test_hasRoles_WithBitmap() public {
        address target = makeAddr("TARGET");

        // Grant multiple roles
        Roles.add(target, USER_ROLE);
        Roles.add(target, OTHER_ROLE);

        // Test _hasRoles with combined bitmap
        uint256 combinedRoles = Role.unwrap(USER_ROLE) | Role.unwrap(OTHER_ROLE);
        assertTrue(Roles._hasRoles(combinedRoles, target));

        // Test with non-matching bitmap
        uint256 otherRoles = Role.unwrap(ADMIN_ROLE);
        assertFalse(Roles._hasRoles(otherRoles, target));
    }

    function testFuzz_role_Creation(uint8 roleId) public pure {
        Role r = Roles.role(roleId);
        assertEq(Role.unwrap(r), 1 << roleId);
    }

    function testFuzz_roleAssignment(address user, uint8 roleId) public {
        Role r = Roles.role(roleId);
        Roles.add(user, r);
        assertTrue(Roles.hasRoles(user, r));

        Roles.remove(user, r);
        assertFalse(Roles.hasRoles(user, r));
    }

}
