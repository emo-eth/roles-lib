// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Role, Roles } from "./Roles.sol";

/**
 * @title RolesExample
 * @notice Comprehensive example of role-based access control using the Roles library
 * @dev Demonstrates various role combinations, checks, and management patterns
 */
contract RolesExample {

    // Define roles as immutable constants
    // Each role should use a unique ID from 0-255
    Role public constant ADMIN = Roles._ROLE_0;
    Role public constant MINTER = Roles._ROLE_1;
    Role public constant PAUSER = Roles._ROLE_2;
    Role public constant UPGRADER = Roles._ROLE_3;
    Role public constant TREASURER = Roles._ROLE_4;

    // Common role combinations can be pre-defined
    Role public immutable ADMIN_OR_MINTER;
    Role public immutable EMERGENCY_ROLES; // Admin + Pauser

    // Events for the example contract
    event TokensMinted(address indexed to, uint256 amount);
    event ContractPaused(address indexed by);
    event FundsManaged(address indexed by, uint256 amount);

    /// @dev Sets up role combinations during construction
    constructor() {
        ADMIN_OR_MINTER = ADMIN.combine(MINTER);
        EMERGENCY_ROLES = ADMIN.combine(PAUSER);

        // Grant admin role to deployer
        Roles.add(msg.sender, ADMIN);
    }

    modifier onlyAdmin() {
        Roles.authAny(msg.sender, ADMIN);
        _;
    }

    /**
     * @notice Demonstrates single role check
     * @dev Only ADMIN role can call this function
     */
    function adminOnlyFunction() external view {
        Roles.authAny(msg.sender, ADMIN);
        // Admin-only logic would go here
    }

    /**
     * @notice Demonstrates checking for one of multiple roles
     * @dev Caller must have either ADMIN or MINTER role
     */
    function adminOrMinterFunction() external view {
        Roles.authAny(msg.sender, ADMIN_OR_MINTER);
        // Admin or minter logic would go here
    }

    /**
     * @notice Shows how to check for multiple roles in custom combinations
     * @dev Can use combine() inline for dynamic role combinations
     */
    function exclusiveRoleCheck() external view {
        // Caller must have both TREASURER AND MINTER role
        Roles.authAll(msg.sender, TREASURER.combine(MINTER));
    }

    /**
     * @notice Shows how to check for multiple roles in custom combinations
     * @dev Can use combine() inline for dynamic role combinations
     */
    function complexRoleCheck() external view {
        // Caller must have either ADMIN role or both TREASURER AND MINTER role
        require(
            Roles.hasAllRoles(msg.sender, TREASURER.combine(MINTER))
                || Roles.hasRoles(msg.sender, ADMIN),
            Roles.NotAllowed()
        );
    }

    /**
     * @notice Example of role management function
     * @dev Only admin can call this
     * @param account Address to update roles for
     * @param role Role to grant or revoke
     * @param shouldAdd True to add role, false to remove
     */
    function updateRole(address account, Role role, bool shouldAdd) external onlyAdmin {
        // Check admin privileges
        Roles.authAny(msg.sender, ADMIN);

        // Prevent removing admin role from last admin
        if (Role.unwrap(role) == Role.unwrap(ADMIN) && !shouldAdd) {
            require(Roles.getRoles(msg.sender) != Role.unwrap(ADMIN), "Cannot remove last admin");
        }

        Roles.update(account, role, shouldAdd);
    }

    /**
     * @notice Example of batch role management
     * @dev Only admin can call this
     * @param accounts Addresses to update roles for
     * @param role Role to grant or revoke
     * @param shouldAdd True to add role, false to remove
     */
    function batchUpdateRole(address[] calldata accounts, Role role, bool shouldAdd) external {
        Roles.authAny(msg.sender, ADMIN);

        for (uint256 i = 0; i < accounts.length; i++) {
            Roles.update(accounts[i], role, shouldAdd);
        }
    }

    /**
     * @notice Example of checking multiple roles for different actions
     * @dev Shows how to handle different privilege levels
     * @param amount Amount of tokens to mint
     */
    function mintWithPrivilegeCheck(uint256 amount) external {
        // Different amount thresholds require different roles
        if (amount > 1000e18) {
            // Large mints require admin
            Roles.authAny(msg.sender, ADMIN);
        } else if (amount > 100e18) {
            // Medium mints require admin or treasurer
            Roles.authAny(msg.sender, ADMIN.combine(TREASURER));
        } else {
            // Small mints can be done by any privileged role
            Roles.authAny(msg.sender, ADMIN_OR_MINTER);
        }

        emit TokensMinted(msg.sender, amount);
    }

    /**
     * @notice Demonstrates how to check current roles
     * @param account Address to check roles for
     * @return bitmap Bitmap of all roles the account has
     */
    function viewRoles(address account) external view returns (uint256 bitmap) {
        bitmap = Roles.getRoles(account);

        // Can also check individual roles
        // bool isAdmin = Roles.hasRoles(account, ADMIN);
        // bool isMinter = Roles.hasRoles(account, MINTER);
        // bool hasEmergencyRoles = Roles.hasRoles(account, EMERGENCY_ROLES);

        // Use these bools for additional logic if needed
        return bitmap;
    }

    function hasRoles(address account, Role role) external view returns (bool) {
        return Roles.hasRoles(account, role);
    }

}
