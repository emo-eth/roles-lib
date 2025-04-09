# Roles

Efficient library for managing up to 256 permissioned "roles" in a smart contract by using bitmaps.

## What is it?

Roles is an experiment in smart contract composition in Solidity.

`Roles.sol` is not a `contract`; it is a `library` which uses [EIP-7201](https://eips.ethereum.org/EIPS/eip-7201) namespaced storage for reads and writes, which means it can be used in any contract because its internal methods and storage are namespaced. Namespaced storage is by-default upgrade-safe.

A `Role` is also a custom type around a `uint256` which by default has methods mapped to it for checking and authorizing calls, eg

```solidity
Role constant ADMIN = Roles._ROLE_0;
Role constant TREASURER = Roles._ROLE_1;
Role constant MINTER = Roles._ROLE_2;


function example() {
    // check a single role
    bool isAdmin = Roles.hasRoles(msg.sender, ADMIN);
    // check for any of a set of roles
    bool isTreasurerOrMinter = Roles.hasRoles(msg.sender, TREASURER.combine(MINTER));
    // check for all of a set of roles
    bool isTreasurerAndMinter = Roles.hasAllRoles(msg.sender, TREASURER.combine(MINTER));


    // check and revert with `error NotAllowed()` if not authorized
    Roles.authAny(msg.sender, ADMIN);
    // check and revert with `error NotAllowed()` if not authorized for any of a set of roles
    Roles.authAny(msg.sender, TREASURER.combine(MINTER));
    // check and revert with `error NotAllowed()` if not authorized for all of a set of roles
    Roles.authAll(msg.sender, TREASURER.combine(MINTER));


    // add a role to an account
    Roles.add(msg.sender, TREASURER);
    // add multiple roles to an account
    Roles.add(msg.sender, TREASURER.combine(MINTER));
    // remove a role from an account
    Roles.remove(msg.sender, TREASURER);
    // remove multiple roles from an account
    Roles.remove(msg.sender, TREASURER.combine(MINTER));
    // update a role for an account
    Roles.update(msg.sender, MINTER, true);
    Roles.update(msg.sender, TREASURER, false);
}
```
