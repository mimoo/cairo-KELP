#
# KELP implementation (https://eprint.iacr.org/2021/289.pdf)
#

%lang starknet
%builtins pedersen range_check ecdsa bitwise

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    get_contract_address, 
    get_caller_address,
    get_block_timestamp
)
from starkware.cairo.common.math import (
    assert_lt,
    assert_not_equal,
    assert_not_zero,
    split_felt
)
from starkware.cairo.common.math_cmp import (
    is_le
)

from starkware.starknet.common.syscalls import (
    storage_read, 
    storage_write
)
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.hash import hash2

#
# ERC-20 interface
# 

@contract_interface
namespace IERC20:
    func name() -> (name: felt):
    end

    func symbol() -> (symbol: felt):
    end

    func decimals() -> (decimals: felt):
    end

    func totalSupply() -> (totalSupply: Uint256):
    end

    func balanceOf(account: felt) -> (balance: Uint256):
    end

    func allowance(owner: felt, spender: felt) -> (remaining: Uint256):
    end

    func transfer(recipient: felt, amount: Uint256) -> (success: felt):
    end

    func transferFrom(
            sender: felt, 
            recipient: felt, 
            amount: Uint256
        ) -> (success: felt):
    end

    func approve(spender: felt, amount: Uint256) -> (success: felt):
    end
end

#
# Owner logic
#

# stores the owner of the contract
@storage_var
func owner() -> (owner_address: felt):
end

@constructor
func constructor{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(owner_address : felt):
    owner.write(owner_address)
    return ()
end

# helper to assert that we are the owner
func assert_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    let (caller_address) = get_caller_address()
    let (owner_address) = owner.read()
    assert owner_address = caller_address
    return ()
end

func change_owner{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(new_owner):
    assert_owner()
    let (caller_address) = get_caller_address()
    owner.write(new_owner)
    return ()
end

#
# KELP logic
#

# time you have to reveal a commit
const expired_commit = 1000

# time you have to claim a revealed commit
const expired_claim = 5000

# fee to start recovery process
const fee_to_commit = 1000000

# fee for the second step of the recovery
const fee_to_reveal = 1000000

# the address of the token used for fees 
# (most likely we want to set this to the ETH proxy contract)
const token_address = 0x1

# stores commitments, and if they are already used
@storage_var 
func commitments(commitment: felt) -> (commit_time: felt):
end

# the time of the latest commit
# used to prevent two commits in a single block
@storage_var
func latest_commit_time() -> (timestamp: felt):
end

# the active claim (there can only be one)
# defaults to 0
@storage_var
func active_claim() -> (active_commitment: felt):
end

# the time of the latest claim reveal
# defaults to 0
@storage_var 
func last_reveal_time() -> (timestamp: felt):
end

# step 1
# ------
# start the process to claim ownership of this contract
# via a commitment = H(address_c, address_r, nonce)
# (to transfer ownership of address_c to address_r)
@external
func commit{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(commitment):
    # collect fee
    let (sender) = get_caller_address()
    let (recipient) = get_contract_address()
    let split = split_felt(fee_to_commit)
    let amount = Uint256(low=split.low, high=split.high)

    let (success) = IERC20.transferFrom(
            contract_address=token_address,
            sender=sender, 
            recipient=recipient,
            amount=amount
        )
    assert_not_zero(success)

    # we prevent two commitments in a block
    let (timestamp) = latest_commit_time.read()
    let (commit_time) = get_block_timestamp()
    assert_lt(timestamp, commit_time)

    # we store the commit only if it's not already there
    let (commit_time) = commitments.read(commitment)
    assert commit_time = 0
    commitments.write(commitment, commit_time)

    return ()
end

# step 2
# ------
# reveal your previous commitment
@external
func reveal{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(commitment, address_c, address_r, nonce):
    alloc_locals

    # collect fee
    let (sender) = get_caller_address()
    let (recipient) = get_contract_address()
    let split = split_felt(fee_to_reveal)
    let amount = Uint256(low=split.low, high=split.high)

    let (success) = IERC20.transferFrom(
            contract_address=token_address,
            sender=sender, 
            recipient=recipient,
            amount=amount
        )
    assert_not_zero(success)

    # address_c?
    let (owner_address) = owner.read()
    assert owner_address = address_c

    # address_r
    # if we want, we could also enforce that address_r is the sender, 
    # but that could prevent some (useful?) usecases
    assert_not_equal(owner_address, address_r)

    # retrieve commitment
    let (local commit_time) = commitments.read(commitment)

    # check expiration
    let (reveal_time) = get_block_timestamp()
    let time_ellapsed = reveal_time - commit_time
    assert_lt (time_ellapsed, expired_commit)

    # open commitment
    let (hash) = hash2{hash_ptr=pedersen_ptr}(address_c, address_r)
    let (hash) = hash2{hash_ptr=pedersen_ptr}(hash, nonce)
    assert hash = commitment

    # compare with active claim
    # WARNING: WOOT. What if someone submits a commitment in the same block, as they see your claim? You need to make sure that there's no other "active" commitments when you submit yours
    let (local other_commitment) = active_claim.read()
    let (local other_time) = commitments.read(other_commitment)

    # if not expired, make sure our commit is more ancient
    let time_ellapsed = reveal_time - other_time
    let (local not_expired) = is_le(time_ellapsed, expired_commit)


    # TODO: fix bug https://www.cairo-lang.org/docs/how_cairo_works/builtins.html#revoked-implicit-arguments
    if other_commitment != 0:
        if not_expired == 1:
            assert_lt(commit_time, other_time)
            tempvar range_check_ptr = range_check_ptr
        else:
            tempvar range_check_ptr = range_check_ptr
        end
    else:
        tempvar range_check_ptr = range_check_ptr
    end

    # set active claim
    active_claim.write(commitment)
    last_reveal_time.write(reveal_time)

    # change owner
    #    owner.write(address_r)
    return ()
end

# step 3
# ------
# claim the contract
@external
func claim{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(address_c, address_r, nonce):
    # enforce that there is a commitment
    let (commitment) = active_claim.read()
    assert_not_zero(commitment)

    # check that enough time has passed since the reveal
    let (claim_time) = get_block_timestamp()
    let (reveal_time) = last_reveal_time.read()
    let time_ellapsed = claim_time - reveal_time
    assert_lt (time_ellapsed, expired_claim)

    # open commitment
    let (hash) = hash2{hash_ptr=pedersen_ptr}(address_c, address_r)
    let (hash) = hash2{hash_ptr=pedersen_ptr}(hash, nonce)
    assert hash = commitment

    # change owner
    owner.write(address_r)

    return ()
end

# bonus
# -----
# challenge a fraudulent claim
@external
func challenge{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    assert_owner()

    # overwrite any active claim
    active_claim.write(0)

    return ()
end

#
# interaction with other contracts
#

# interact with ERC-20 contracts
@external
func transfer{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(contract_address: felt, recipient: felt, amount: Uint256) -> (success: felt):

    # owner?
    assert_owner()

    # call the token contract
    let (success) = IERC20.transfer(
        contract_address=contract_address,
        recipient=recipient,
        amount=amount
    )
    return (success=success)
end

# other functions:
# maybe we should just implement a general execute function like https://github.com/OpenZeppelin/cairo-contracts/blob/main/src/openzeppelin/account/library.cairo#L187
