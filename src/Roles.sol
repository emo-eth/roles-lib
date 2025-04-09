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

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    ///@custom:storage-location eip7201:Roles.storage
    bytes32 constant ROLES_STORAGE_SLOT =
        0xe530394f899cb30908c6b27aeebe978aff47d8c53e072b76283131df0075b300;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event RoleGranted(address indexed account, Role indexed role);
    event RoleRevoked(address indexed account, Role indexed role);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error NotAllowed();

    /*//////////////////////////////////////////////////////////////
                            STORAGE ACCESS
    //////////////////////////////////////////////////////////////*/

    /// @dev Get the storage location for roles
    /// @return s Storage pointer to RolesStorage
    function getStorage() internal pure returns (RolesStorage storage s) {
        assembly {
            s.slot := ROLES_STORAGE_SLOT
        }
    }

    /*//////////////////////////////////////////////////////////////
                            ROLE MANAGEMENT
    //////////////////////////////////////////////////////////////*/

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

    /// @dev Check if a role contains another role
    function hasRoles(Role _role, Role _roles) internal pure returns (bool) {
        return _hasRoles(Role.unwrap(_role), _roles);
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

    /// @dev Check if an account has all specified roles
    /// @param account Address to check roles for
    /// @param _role Required role(s) to check for
    /// @return True if account has all specified roles, false otherwise
    function hasAllRoles(address account, Role _role) internal view returns (bool) {
        RolesStorage storage s = Roles.getStorage();
        Role userRoles = s.roles[account];
        uint256 userBitmap = Role.unwrap(userRoles);
        return _hasAllRoles(userBitmap, _role);
    }

    /// @dev Internal helper to check if a bitmap contains all specified roles
    /// @param userBitmap Bitmap of user's current roles
    /// @param _role Required role(s) to check for
    /// @return True if bitmap has all specified roles, false otherwise
    function _hasAllRoles(uint256 userBitmap, Role _role) internal pure returns (bool) {
        // & userBitmap with role; this will return a bitmap with only the roles that are present in
        // both the user's roles and the required role
        uint256 masked = userBitmap & Role.unwrap(_role);
        // if the masked bitmap is equal to the required role, then the user has all the roles
        return masked == Role.unwrap(_role);
    }

    /*//////////////////////////////////////////////////////////////
                            ROLE CONSTANTS
                    For declaring roles in contracts
                    Each represents a single bit position
                    from 0-255 in the role bitmap
    //////////////////////////////////////////////////////////////*/

    Role constant _ROLE_0 = Role.wrap(1 << 0);
    Role constant _ROLE_1 = Role.wrap(1 << 1);
    Role constant _ROLE_2 = Role.wrap(1 << 2);
    Role constant _ROLE_3 = Role.wrap(1 << 3);
    Role constant _ROLE_4 = Role.wrap(1 << 4);
    Role constant _ROLE_5 = Role.wrap(1 << 5);
    Role constant _ROLE_6 = Role.wrap(1 << 6);
    Role constant _ROLE_7 = Role.wrap(1 << 7);
    Role constant _ROLE_8 = Role.wrap(1 << 8);
    Role constant _ROLE_9 = Role.wrap(1 << 9);
    Role constant _ROLE_10 = Role.wrap(1 << 10);
    Role constant _ROLE_11 = Role.wrap(1 << 11);
    Role constant _ROLE_12 = Role.wrap(1 << 12);
    Role constant _ROLE_13 = Role.wrap(1 << 13);
    Role constant _ROLE_14 = Role.wrap(1 << 14);
    Role constant _ROLE_15 = Role.wrap(1 << 15);
    Role constant _ROLE_16 = Role.wrap(1 << 16);
    Role constant _ROLE_17 = Role.wrap(1 << 17);
    Role constant _ROLE_18 = Role.wrap(1 << 18);
    Role constant _ROLE_19 = Role.wrap(1 << 19);
    Role constant _ROLE_20 = Role.wrap(1 << 20);
    Role constant _ROLE_21 = Role.wrap(1 << 21);
    Role constant _ROLE_22 = Role.wrap(1 << 22);
    Role constant _ROLE_23 = Role.wrap(1 << 23);
    Role constant _ROLE_24 = Role.wrap(1 << 24);
    Role constant _ROLE_25 = Role.wrap(1 << 25);
    Role constant _ROLE_26 = Role.wrap(1 << 26);
    Role constant _ROLE_27 = Role.wrap(1 << 27);
    Role constant _ROLE_28 = Role.wrap(1 << 28);
    Role constant _ROLE_29 = Role.wrap(1 << 29);
    Role constant _ROLE_30 = Role.wrap(1 << 30);
    Role constant _ROLE_31 = Role.wrap(1 << 31);
    Role constant _ROLE_32 = Role.wrap(1 << 32);
    Role constant _ROLE_33 = Role.wrap(1 << 33);
    Role constant _ROLE_34 = Role.wrap(1 << 34);
    Role constant _ROLE_35 = Role.wrap(1 << 35);
    Role constant _ROLE_36 = Role.wrap(1 << 36);
    Role constant _ROLE_37 = Role.wrap(1 << 37);
    Role constant _ROLE_38 = Role.wrap(1 << 38);
    Role constant _ROLE_39 = Role.wrap(1 << 39);
    Role constant _ROLE_40 = Role.wrap(1 << 40);
    Role constant _ROLE_41 = Role.wrap(1 << 41);
    Role constant _ROLE_42 = Role.wrap(1 << 42);
    Role constant _ROLE_43 = Role.wrap(1 << 43);
    Role constant _ROLE_44 = Role.wrap(1 << 44);
    Role constant _ROLE_45 = Role.wrap(1 << 45);
    Role constant _ROLE_46 = Role.wrap(1 << 46);
    Role constant _ROLE_47 = Role.wrap(1 << 47);
    Role constant _ROLE_48 = Role.wrap(1 << 48);
    Role constant _ROLE_49 = Role.wrap(1 << 49);
    Role constant _ROLE_50 = Role.wrap(1 << 50);
    Role constant _ROLE_51 = Role.wrap(1 << 51);
    Role constant _ROLE_52 = Role.wrap(1 << 52);
    Role constant _ROLE_53 = Role.wrap(1 << 53);
    Role constant _ROLE_54 = Role.wrap(1 << 54);
    Role constant _ROLE_55 = Role.wrap(1 << 55);
    Role constant _ROLE_56 = Role.wrap(1 << 56);
    Role constant _ROLE_57 = Role.wrap(1 << 57);
    Role constant _ROLE_58 = Role.wrap(1 << 58);
    Role constant _ROLE_59 = Role.wrap(1 << 59);
    Role constant _ROLE_60 = Role.wrap(1 << 60);
    Role constant _ROLE_61 = Role.wrap(1 << 61);
    Role constant _ROLE_62 = Role.wrap(1 << 62);
    Role constant _ROLE_63 = Role.wrap(1 << 63);
    Role constant _ROLE_64 = Role.wrap(1 << 64);
    Role constant _ROLE_65 = Role.wrap(1 << 65);
    Role constant _ROLE_66 = Role.wrap(1 << 66);
    Role constant _ROLE_67 = Role.wrap(1 << 67);
    Role constant _ROLE_68 = Role.wrap(1 << 68);
    Role constant _ROLE_69 = Role.wrap(1 << 69);
    Role constant _ROLE_70 = Role.wrap(1 << 70);
    Role constant _ROLE_71 = Role.wrap(1 << 71);
    Role constant _ROLE_72 = Role.wrap(1 << 72);
    Role constant _ROLE_73 = Role.wrap(1 << 73);
    Role constant _ROLE_74 = Role.wrap(1 << 74);
    Role constant _ROLE_75 = Role.wrap(1 << 75);
    Role constant _ROLE_76 = Role.wrap(1 << 76);
    Role constant _ROLE_77 = Role.wrap(1 << 77);
    Role constant _ROLE_78 = Role.wrap(1 << 78);
    Role constant _ROLE_79 = Role.wrap(1 << 79);
    Role constant _ROLE_80 = Role.wrap(1 << 80);
    Role constant _ROLE_81 = Role.wrap(1 << 81);
    Role constant _ROLE_82 = Role.wrap(1 << 82);
    Role constant _ROLE_83 = Role.wrap(1 << 83);
    Role constant _ROLE_84 = Role.wrap(1 << 84);
    Role constant _ROLE_85 = Role.wrap(1 << 85);
    Role constant _ROLE_86 = Role.wrap(1 << 86);
    Role constant _ROLE_87 = Role.wrap(1 << 87);
    Role constant _ROLE_88 = Role.wrap(1 << 88);
    Role constant _ROLE_89 = Role.wrap(1 << 89);
    Role constant _ROLE_90 = Role.wrap(1 << 90);
    Role constant _ROLE_91 = Role.wrap(1 << 91);
    Role constant _ROLE_92 = Role.wrap(1 << 92);
    Role constant _ROLE_93 = Role.wrap(1 << 93);
    Role constant _ROLE_94 = Role.wrap(1 << 94);
    Role constant _ROLE_95 = Role.wrap(1 << 95);
    Role constant _ROLE_96 = Role.wrap(1 << 96);
    Role constant _ROLE_97 = Role.wrap(1 << 97);
    Role constant _ROLE_98 = Role.wrap(1 << 98);
    Role constant _ROLE_99 = Role.wrap(1 << 99);
    Role constant _ROLE_100 = Role.wrap(1 << 100);
    Role constant _ROLE_101 = Role.wrap(1 << 101);
    Role constant _ROLE_102 = Role.wrap(1 << 102);
    Role constant _ROLE_103 = Role.wrap(1 << 103);
    Role constant _ROLE_104 = Role.wrap(1 << 104);
    Role constant _ROLE_105 = Role.wrap(1 << 105);
    Role constant _ROLE_106 = Role.wrap(1 << 106);
    Role constant _ROLE_107 = Role.wrap(1 << 107);
    Role constant _ROLE_108 = Role.wrap(1 << 108);
    Role constant _ROLE_109 = Role.wrap(1 << 109);
    Role constant _ROLE_110 = Role.wrap(1 << 110);
    Role constant _ROLE_111 = Role.wrap(1 << 111);
    Role constant _ROLE_112 = Role.wrap(1 << 112);
    Role constant _ROLE_113 = Role.wrap(1 << 113);
    Role constant _ROLE_114 = Role.wrap(1 << 114);
    Role constant _ROLE_115 = Role.wrap(1 << 115);
    Role constant _ROLE_116 = Role.wrap(1 << 116);
    Role constant _ROLE_117 = Role.wrap(1 << 117);
    Role constant _ROLE_118 = Role.wrap(1 << 118);
    Role constant _ROLE_119 = Role.wrap(1 << 119);
    Role constant _ROLE_120 = Role.wrap(1 << 120);
    Role constant _ROLE_121 = Role.wrap(1 << 121);
    Role constant _ROLE_122 = Role.wrap(1 << 122);
    Role constant _ROLE_123 = Role.wrap(1 << 123);
    Role constant _ROLE_124 = Role.wrap(1 << 124);
    Role constant _ROLE_125 = Role.wrap(1 << 125);
    Role constant _ROLE_126 = Role.wrap(1 << 126);
    Role constant _ROLE_127 = Role.wrap(1 << 127);
    Role constant _ROLE_128 = Role.wrap(1 << 128);
    Role constant _ROLE_129 = Role.wrap(1 << 129);
    Role constant _ROLE_130 = Role.wrap(1 << 130);
    Role constant _ROLE_131 = Role.wrap(1 << 131);
    Role constant _ROLE_132 = Role.wrap(1 << 132);
    Role constant _ROLE_133 = Role.wrap(1 << 133);
    Role constant _ROLE_134 = Role.wrap(1 << 134);
    Role constant _ROLE_135 = Role.wrap(1 << 135);
    Role constant _ROLE_136 = Role.wrap(1 << 136);
    Role constant _ROLE_137 = Role.wrap(1 << 137);
    Role constant _ROLE_138 = Role.wrap(1 << 138);
    Role constant _ROLE_139 = Role.wrap(1 << 139);
    Role constant _ROLE_140 = Role.wrap(1 << 140);
    Role constant _ROLE_141 = Role.wrap(1 << 141);
    Role constant _ROLE_142 = Role.wrap(1 << 142);
    Role constant _ROLE_143 = Role.wrap(1 << 143);
    Role constant _ROLE_144 = Role.wrap(1 << 144);
    Role constant _ROLE_145 = Role.wrap(1 << 145);
    Role constant _ROLE_146 = Role.wrap(1 << 146);
    Role constant _ROLE_147 = Role.wrap(1 << 147);
    Role constant _ROLE_148 = Role.wrap(1 << 148);
    Role constant _ROLE_149 = Role.wrap(1 << 149);
    Role constant _ROLE_150 = Role.wrap(1 << 150);
    Role constant _ROLE_151 = Role.wrap(1 << 151);
    Role constant _ROLE_152 = Role.wrap(1 << 152);
    Role constant _ROLE_153 = Role.wrap(1 << 153);
    Role constant _ROLE_154 = Role.wrap(1 << 154);
    Role constant _ROLE_155 = Role.wrap(1 << 155);
    Role constant _ROLE_156 = Role.wrap(1 << 156);
    Role constant _ROLE_157 = Role.wrap(1 << 157);
    Role constant _ROLE_158 = Role.wrap(1 << 158);
    Role constant _ROLE_159 = Role.wrap(1 << 159);
    Role constant _ROLE_160 = Role.wrap(1 << 160);
    Role constant _ROLE_161 = Role.wrap(1 << 161);
    Role constant _ROLE_162 = Role.wrap(1 << 162);
    Role constant _ROLE_163 = Role.wrap(1 << 163);
    Role constant _ROLE_164 = Role.wrap(1 << 164);
    Role constant _ROLE_165 = Role.wrap(1 << 165);
    Role constant _ROLE_166 = Role.wrap(1 << 166);
    Role constant _ROLE_167 = Role.wrap(1 << 167);
    Role constant _ROLE_168 = Role.wrap(1 << 168);
    Role constant _ROLE_169 = Role.wrap(1 << 169);
    Role constant _ROLE_170 = Role.wrap(1 << 170);
    Role constant _ROLE_171 = Role.wrap(1 << 171);
    Role constant _ROLE_172 = Role.wrap(1 << 172);
    Role constant _ROLE_173 = Role.wrap(1 << 173);
    Role constant _ROLE_174 = Role.wrap(1 << 174);
    Role constant _ROLE_175 = Role.wrap(1 << 175);
    Role constant _ROLE_176 = Role.wrap(1 << 176);
    Role constant _ROLE_177 = Role.wrap(1 << 177);
    Role constant _ROLE_178 = Role.wrap(1 << 178);
    Role constant _ROLE_179 = Role.wrap(1 << 179);
    Role constant _ROLE_180 = Role.wrap(1 << 180);
    Role constant _ROLE_181 = Role.wrap(1 << 181);
    Role constant _ROLE_182 = Role.wrap(1 << 182);
    Role constant _ROLE_183 = Role.wrap(1 << 183);
    Role constant _ROLE_184 = Role.wrap(1 << 184);
    Role constant _ROLE_185 = Role.wrap(1 << 185);
    Role constant _ROLE_186 = Role.wrap(1 << 186);
    Role constant _ROLE_187 = Role.wrap(1 << 187);
    Role constant _ROLE_188 = Role.wrap(1 << 188);
    Role constant _ROLE_189 = Role.wrap(1 << 189);
    Role constant _ROLE_190 = Role.wrap(1 << 190);
    Role constant _ROLE_191 = Role.wrap(1 << 191);
    Role constant _ROLE_192 = Role.wrap(1 << 192);
    Role constant _ROLE_193 = Role.wrap(1 << 193);
    Role constant _ROLE_194 = Role.wrap(1 << 194);
    Role constant _ROLE_195 = Role.wrap(1 << 195);
    Role constant _ROLE_196 = Role.wrap(1 << 196);
    Role constant _ROLE_197 = Role.wrap(1 << 197);
    Role constant _ROLE_198 = Role.wrap(1 << 198);
    Role constant _ROLE_199 = Role.wrap(1 << 199);
    Role constant _ROLE_200 = Role.wrap(1 << 200);
    Role constant _ROLE_201 = Role.wrap(1 << 201);
    Role constant _ROLE_202 = Role.wrap(1 << 202);
    Role constant _ROLE_203 = Role.wrap(1 << 203);
    Role constant _ROLE_204 = Role.wrap(1 << 204);
    Role constant _ROLE_205 = Role.wrap(1 << 205);
    Role constant _ROLE_206 = Role.wrap(1 << 206);
    Role constant _ROLE_207 = Role.wrap(1 << 207);
    Role constant _ROLE_208 = Role.wrap(1 << 208);
    Role constant _ROLE_209 = Role.wrap(1 << 209);
    Role constant _ROLE_210 = Role.wrap(1 << 210);
    Role constant _ROLE_211 = Role.wrap(1 << 211);
    Role constant _ROLE_212 = Role.wrap(1 << 212);
    Role constant _ROLE_213 = Role.wrap(1 << 213);
    Role constant _ROLE_214 = Role.wrap(1 << 214);
    Role constant _ROLE_215 = Role.wrap(1 << 215);
    Role constant _ROLE_216 = Role.wrap(1 << 216);
    Role constant _ROLE_217 = Role.wrap(1 << 217);
    Role constant _ROLE_218 = Role.wrap(1 << 218);
    Role constant _ROLE_219 = Role.wrap(1 << 219);
    Role constant _ROLE_220 = Role.wrap(1 << 220);
    Role constant _ROLE_221 = Role.wrap(1 << 221);
    Role constant _ROLE_222 = Role.wrap(1 << 222);
    Role constant _ROLE_223 = Role.wrap(1 << 223);
    Role constant _ROLE_224 = Role.wrap(1 << 224);
    Role constant _ROLE_225 = Role.wrap(1 << 225);
    Role constant _ROLE_226 = Role.wrap(1 << 226);
    Role constant _ROLE_227 = Role.wrap(1 << 227);
    Role constant _ROLE_228 = Role.wrap(1 << 228);
    Role constant _ROLE_229 = Role.wrap(1 << 229);
    Role constant _ROLE_230 = Role.wrap(1 << 230);
    Role constant _ROLE_231 = Role.wrap(1 << 231);
    Role constant _ROLE_232 = Role.wrap(1 << 232);
    Role constant _ROLE_233 = Role.wrap(1 << 233);
    Role constant _ROLE_234 = Role.wrap(1 << 234);
    Role constant _ROLE_235 = Role.wrap(1 << 235);
    Role constant _ROLE_236 = Role.wrap(1 << 236);
    Role constant _ROLE_237 = Role.wrap(1 << 237);
    Role constant _ROLE_238 = Role.wrap(1 << 238);
    Role constant _ROLE_239 = Role.wrap(1 << 239);
    Role constant _ROLE_240 = Role.wrap(1 << 240);
    Role constant _ROLE_241 = Role.wrap(1 << 241);
    Role constant _ROLE_242 = Role.wrap(1 << 242);
    Role constant _ROLE_243 = Role.wrap(1 << 243);
    Role constant _ROLE_244 = Role.wrap(1 << 244);
    Role constant _ROLE_245 = Role.wrap(1 << 245);
    Role constant _ROLE_246 = Role.wrap(1 << 246);
    Role constant _ROLE_247 = Role.wrap(1 << 247);
    Role constant _ROLE_248 = Role.wrap(1 << 248);
    Role constant _ROLE_249 = Role.wrap(1 << 249);
    Role constant _ROLE_250 = Role.wrap(1 << 250);
    Role constant _ROLE_251 = Role.wrap(1 << 251);
    Role constant _ROLE_252 = Role.wrap(1 << 252);
    Role constant _ROLE_253 = Role.wrap(1 << 253);
    Role constant _ROLE_254 = Role.wrap(1 << 254);
    Role constant _ROLE_255 = Role.wrap(1 << 255);

}
