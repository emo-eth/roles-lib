// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Role-Based Access Control Library
/// @notice Efficient bitwise role management with type safety
/// @dev Uses EIP-7201 for namespaced storage pattern
struct RolesStorage {
    mapping(address => Role) roles;
}

/// @dev Type-safe wrapper around uint256 for role values
type Role is uint256;

using Roles for Role global;

library Roles {

    ///@custom:storage-location eip7201:Roles.storage
    bytes32 constant ROLES_STORAGE_SLOT =
        0xe530394f899cb30908c6b27aeebe978aff47d8c53e072b76283131df0075b300;

    error NotAllowed();

    /// @dev Emitted when a role is granted to an account
    event RoleGranted(address indexed account, Role indexed role);
    /// @dev Emitted when a role is revoked from an account
    event RoleRevoked(address indexed account, Role indexed role);

    /// @dev Get the storage location for roles
    /// @return s Storage pointer to RolesStorage
    function getStorage() internal pure returns (RolesStorage storage s) {
        assembly {
            s.slot := ROLES_STORAGE_SLOT
        }
    }

    /// @dev Create a role from an ID
    /// @param roleId The ID to create a role from (0-255)
    /// @return r The created role (1 << roleId)
    function role(uint8 roleId) internal pure returns (Role r) {
        assembly {
            r := shl(roleId, 1)
        }
    }

    /// @dev Check if a role bitmap contains a specific role
    /// @param combinedRoles Bitmap of roles
    /// @param _role Role to check for
    /// @return True if role is present
    function _hasRoles(uint256 combinedRoles, Role _role) internal pure returns (bool) {
        return combinedRoles & Role.unwrap(_role) != 0;
    }

    /// @dev Check if an account's roles contain any of the roles in a bitmap
    /// @param combinedRoles Bitmap of roles to check against
    /// @param account Address to check roles for
    /// @return True if account has any of the roles
    function _hasRoles(uint256 combinedRoles, address account) internal view returns (bool) {
        RolesStorage storage $ = getStorage();
        Role retrieved = $.roles[account];
        return _hasRoles(combinedRoles, retrieved);
    }

    /// @dev Check if an account has a specific role
    /// @param account Address to check
    /// @param _role Role to check for
    /// @return True if account has the role
    function hasRoles(address account, Role _role) internal view returns (bool) {
        return _hasRoles(Role.unwrap(_role), account);
    }

    /// @dev Grant a role to an account
    /// @param account Address to grant role to
    /// @param _role Role to grant
    function add(address account, Role _role) internal {
        RolesStorage storage s = getStorage();
        s.roles[account] = Role.wrap(Role.unwrap(s.roles[account]) | Role.unwrap(_role));
        emit RoleGranted(account, _role);
    }

    /// @dev Remove a role from an account
    /// @param account Address to remove role from
    /// @param _role Role to remove
    function remove(address account, Role _role) internal {
        RolesStorage storage s = getStorage();
        s.roles[account] = Role.wrap(Role.unwrap(s.roles[account]) & ~Role.unwrap(_role));
        emit RoleRevoked(account, _role);
    }

    /// @dev Add or remove a role from an account
    /// @param account Address to update role for
    /// @param _role Role to update
    /// @param addRole True to add role, false to remove
    function update(address account, Role _role, bool addRole) internal {
        if (addRole) {
            add(account, _role);
        } else {
            remove(account, _role);
        }
    }

    /// @dev Revert if account doesn't have role
    /// @param account Address to check
    /// @param _role Required role
    function authAny(address account, Role _role) internal view {
        if (!hasRoles(account, _role)) {
            revert NotAllowed();
        }
    }

    /// @dev Combine two roles into a single role
    /// @param role1 First role
    /// @param role2 Second role
    /// @return Combined role (role1 | role2)
    function combine(Role role1, Role role2) internal pure returns (Role) {
        uint256 combined;
        assembly {
            combined := or(role1, role2)
        }
        return Role.wrap(combined);
    }

    /// @dev Get all roles for an account as a bitmap
    /// @param account Address to get roles for
    /// @return Bitmap of account's roles
    function getRoles(address account) internal view returns (uint256) {
        return Role.unwrap(getStorage().roles[account]);
    }

    /// @dev Revert if account doesn't have all roles
    /// @param account Address to check
    /// @param _role Required role
    function authAll(address account, Role _role) internal view {
        if (!hasAllRoles(account, _role)) {
            revert NotAllowed();
        }
    }

    function hasAllRoles(address account, Role _role) internal view returns (bool) {
        RolesStorage storage s = Roles.getStorage();
        Role userRoles = s.roles[account];
        uint256 userBitmap = Role.unwrap(userRoles);
        return _hasAllRoles(userBitmap, _role);
    }

    function _hasAllRoles(uint256 userBitmap, Role _role) internal pure returns (bool) {
        // & userBitmap with role; this will return a bitmap with only the roles that are present in
        // both the user's roles and the required role
        uint256 masked = userBitmap & Role.unwrap(_role);
        // if the masked bitmap is equal to the required role, then the user has all the roles
        return masked == Role.unwrap(_role);
    }

}
