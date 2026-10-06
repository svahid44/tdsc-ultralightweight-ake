from pathlib import Path
import asyncio
import hashlib
import json

from solana.rpc.async_api import AsyncClient
from solders.instruction import Instruction, AccountMeta
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction


ROOT = Path(__file__).resolve().parents[2]

RPC = "https://api.devnet.solana.com"

PROGRAM_ID = Pubkey.from_string(
    "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
)

NSP_AUTHORITY = Pubkey.from_string(
    "Gd5nHLBUVkdDxKuBVbXUtbTk9s3ZCaztMAn6b9btfPou"
)

NSP_WALLET_PATH = ROOT / "nsp/data/solana_nsp.key"


PHASE2_RESULT_PATH = (
    ROOT / "nsp/data/phase2_registration_complete.json"
)


def instruction_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"global:{name}".encode()
    ).digest()[:8]


def account_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"account:{name}".encode()
    ).digest()[:8]


def read_u32(raw: bytes, offset: int):
    value = int.from_bytes(
        raw[offset:offset + 4],
        "little",
    )

    return value, offset + 4


def decode_smd_record(raw: bytes):
    expected = account_discriminator(
        "SmdRecord"
    )

    if raw[:8] != expected:
        raise RuntimeError(
            "SmdRecord discriminator mismatch"
        )

    offset = 8

    eid_hash = raw[offset:offset + 32]
    offset += 32

    eid_len, offset = read_u32(
        raw,
        offset,
    )

    eid_smd = raw[
        offset:offset + eid_len
    ].decode("utf-8")

    offset += eid_len

    pk_len, offset = read_u32(
        raw,
        offset,
    )
    pk_smd = raw[offset:offset + pk_len]
    offset += pk_len

    a_len, offset = read_u32(
        raw,
        offset,
    )
    a_smd = raw[offset:offset + a_len]
    offset += a_len

    rs_smd = raw[offset]

    return {
        "eid_hash": eid_hash,
        "eid_smd": eid_smd,
        "pk_smd": pk_smd,
        "a_smd": a_smd,
        "rs_smd": rs_smd,
    }


async def main():
    phase2 = json.loads(
        PHASE2_RESULT_PATH.read_text()
    )

    if phase2.get("status") != "PHASE2_COMPLETED":
        raise RuntimeError(
            "Phase 2 completion record not found"
        )

    eid_smd = phase2["eid_smd"]

    eid_hash = hashlib.sha256(
        eid_smd.encode("utf-8")
    ).digest()

    config_pda, _ = Pubkey.find_program_address(
        [b"config"],
        PROGRAM_ID,
    )

    smd_pda, _ = Pubkey.find_program_address(
        [b"smd", eid_hash],
        PROGRAM_ID,
    )

    wallet = Keypair.from_bytes(
        NSP_WALLET_PATH.read_bytes()
    )

    if wallet.pubkey() != NSP_AUTHORITY:
        raise RuntimeError(
            "Wrong NSP Solana wallet loaded"
        )

    print("Program ID:", PROGRAM_ID)
    print("NSP authority:", NSP_AUTHORITY)
    print("Config PDA:", config_pda)
    print("SMD PDA:", smd_pda)

    async with AsyncClient(RPC) as client:
        before = await client.get_account_info(
            smd_pda
        )

        if before.value is None:
            raise RuntimeError(
                "SMD record not found on Solana"
            )

        if before.value.owner != PROGRAM_ID:
            raise RuntimeError(
                "Unexpected SMD account owner"
            )

        decoded_before = decode_smd_record(
            before.value.data
        )

        if decoded_before["eid_smd"] != eid_smd:
            raise RuntimeError(
                "EID_SMD mismatch"
            )

        print("RS_SMD before:", decoded_before["rs_smd"])

        if decoded_before["rs_smd"] == 1:
            print(
                "STATUS: SMD ALREADY REVOKED ON DEVNET"
            )
            return

        if decoded_before["rs_smd"] != 0:
            raise RuntimeError(
                "Unexpected RS_SMD value"
            )



        data = instruction_discriminator(
            "revoke_smd"
        )

        accounts = [
            AccountMeta(
                config_pda,
                is_signer=False,
                is_writable=False,
            ),
            AccountMeta(
                smd_pda,
                is_signer=False,
                is_writable=True,
            ),
            AccountMeta(
                NSP_AUTHORITY,
                is_signer=True,
                is_writable=False,
            ),
        ]

        ix = Instruction(
            PROGRAM_ID,
            data,
            accounts,
        )

        latest = await client.get_latest_blockhash()

        msg = MessageV0.try_compile(
            payer=NSP_AUTHORITY,
            instructions=[ix],
            address_lookup_table_accounts=[],
            recent_blockhash=latest.value.blockhash,
        )

        fee = await client.get_fee_for_message(
            msg
        )

        balance = await client.get_balance(
            NSP_AUTHORITY
        )

        print(
            "Estimated fee:",
            fee.value,
            "lamports"
        )

        print(
            "NSP balance before:",
            balance.value / 1_000_000_000,
            "SOL"
        )

        tx = VersionedTransaction(
            msg,
            [wallet],
        )

        sent = await client.send_transaction(
            tx
        )

        signature = sent.value

        print("Transaction submitted.")
        print("Signature:", signature)

        await client.confirm_transaction(
            signature,
            commitment="confirmed",
            last_valid_block_height=
                latest.value.last_valid_block_height,
        )

        print("Transaction confirmed.")

        after = await client.get_account_info(
            smd_pda
        )

        if after.value is None:
            raise RuntimeError(
                "SMD record disappeared"
            )

        decoded_after = decode_smd_record(
            after.value.data
        )

        print("RS_SMD after:", decoded_after["rs_smd"])

        if decoded_after["rs_smd"] != 1:
            raise RuntimeError(
                "Revocation was not persisted"
            )

        print()
        print(
            "STATUS: SMD-001 REVOKED AND VERIFIED ON DEVNET"
        )


asyncio.run(main())
