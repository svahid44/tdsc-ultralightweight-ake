from pathlib import Path
import asyncio
import hashlib
import json
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from solana.rpc.async_api import AsyncClient

from solders.instruction import Instruction, AccountMeta
from solders.keypair import Keypair
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.transaction import VersionedTransaction






RPC = "https://api.devnet.solana.com"

PROGRAM_ID = Pubkey.from_string(
    "CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ"
)

TUC_AUTHORITY = Pubkey.from_string(
    "CQSBRzGMFdjfTx3Nqaue31N4HEuLeuTUDmJLk9QVN4E2"
)

NSP_AUTHORITY = Pubkey.from_string(
    "Gd5nHLBUVkdDxKuBVbXUtbTk9s3ZCaztMAn6b9btfPou"
)

SYSTEM_PROGRAM = Pubkey.from_string(
    "11111111111111111111111111111111"
)

ROOT = Path(__file__).resolve().parents[2]

TUC_WALLET_PATH = ROOT / "tuc/data/solana_tuc.key"
PENDING_PATH = ROOT / "tuc/data/pending/SMD-001.json"
REGISTRY_PATH = ROOT / "tuc/data/smd_registry.json"






def instruction_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"global:{name}".encode()
    ).digest()[:8]


def account_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"account:{name}".encode()
    ).digest()[:8]






def borsh_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<I", len(raw)) + raw


def borsh_vec_u8(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value






def read_u32(raw: bytes, offset: int):
    value = struct.unpack_from("<I", raw, offset)[0]
    return value, offset + 4


def decode_smd_record(raw: bytes):
    expected_disc = account_discriminator("SmdRecord")

    if raw[:8] != expected_disc:
        raise RuntimeError(
            "SmdRecord discriminator mismatch"
        )

    offset = 8

    stored_eid_hash = raw[offset:offset + 32]
    offset += 32

    eid_len, offset = read_u32(raw, offset)

    eid_smd = raw[
        offset:offset + eid_len
    ].decode("utf-8")
    offset += eid_len

    pk_len, offset = read_u32(raw, offset)

    pk_smd = raw[
        offset:offset + pk_len
    ]
    offset += pk_len

    a_len, offset = read_u32(raw, offset)

    a_smd = raw[
        offset:offset + a_len
    ]
    offset += a_len

    rs_smd = raw[offset]

    return {
        "eid_hash": stored_eid_hash,
        "eid_smd": eid_smd,
        "pk_smd": pk_smd,
        "a_smd": a_smd,
        "rs_smd": rs_smd,
    }






def finalize_local(
    pending,
    eid_hash,
    smd_pda,
    signature,
):
    pending["status"] = "ONCHAIN_INSERTED"
    pending["program_id"] = str(PROGRAM_ID)
    pending["smd_pda"] = str(smd_pda)
    pending["eid_hash_sha256"] = eid_hash.hex()

    if signature is not None:
        pending["insert_tx_signature"] = str(signature)

    PENDING_PATH.write_text(
        json.dumps(pending, indent=2) + "\n"
    )

    PENDING_PATH.chmod(0o600)

    registry = json.loads(
        REGISTRY_PATH.read_text()
    )

    existing = next(
        (
            item
            for item in registry["smds"]
            if item["id_smd"] == pending["id_smd"]
        ),
        None,
    )

    entry = {
        "id_smd": pending["id_smd"],
        "eid_hash_sha256": eid_hash.hex(),
        "smd_pda": str(smd_pda),
        "program_id": str(PROGRAM_ID),
        "status": "ONCHAIN_ACTIVE",
    }

    if existing is None:
        registry["smds"].append(entry)
    else:
        if existing["smd_pda"] != str(smd_pda):
            raise RuntimeError(
                "Local registry contains a different PDA"
            )

        existing.update(entry)

    REGISTRY_PATH.write_text(
        json.dumps(registry, indent=2) + "\n"
    )

    REGISTRY_PATH.chmod(0o600)






async def main():

    pending = json.loads(
        PENDING_PATH.read_text()
    )

    record = pending["ledger_record"]

    id_smd = pending["id_smd"]
    eid_smd = record["eid_smd"]





    eid_hash = hashlib.sha256(
        eid_smd.encode("utf-8")
    ).digest()





    pk_obj = serialization.load_pem_public_key(
        record["pk_smd_pem"].encode("ascii")
    )

    if not isinstance(
        pk_obj.curve,
        ec.SECP256R1
    ):
        raise RuntimeError(
            "PK_SMD is not secp256r1"
        )

    pk_compressed = pk_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )





    a_obj = serialization.load_pem_public_key(
        record["A_smd_pem"].encode("ascii")
    )

    if not isinstance(
        a_obj.curve,
        ec.SECP256R1
    ):
        raise RuntimeError(
            "A_SMD is not secp256r1"
        )

    a_compressed = a_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )

    if len(pk_compressed) != 33:
        raise RuntimeError(
            "PK_SMD compressed size is not 33 bytes"
        )

    if len(a_compressed) != 33:
        raise RuntimeError(
            "A_SMD compressed size is not 33 bytes"
        )





    config_pda, _ = Pubkey.find_program_address(
        [b"config"],
        PROGRAM_ID,
    )

    smd_pda, smd_bump = Pubkey.find_program_address(
        [
            b"smd",
            eid_hash,
        ],
        PROGRAM_ID,
    )





    tuc_wallet = Keypair.from_bytes(
        TUC_WALLET_PATH.read_bytes()
    )

    if tuc_wallet.pubkey() != TUC_AUTHORITY:
        raise RuntimeError(
            "Wrong TUC wallet loaded"
        )

    print("ID_SMD:", id_smd)
    print("Program ID:", PROGRAM_ID)
    print("Config PDA:", config_pda)
    print("SMD PDA:", smd_pda)
    print("SMD PDA bump:", smd_bump)
    print("PK_SMD compressed:", len(pk_compressed), "bytes")
    print("A_SMD compressed:", len(a_compressed), "bytes")
    print("RS_SMD to insert:", record["rs_smd"])
    print()

    if record["rs_smd"] != 0:
        raise RuntimeError(
            "Initial RS_SMD must be 0"
        )

    async with AsyncClient(RPC) as client:





        config_info = await client.get_account_info(
            config_pda
        )

        if config_info.value is None:
            raise RuntimeError(
                "Registry config does not exist"
            )

        if config_info.value.owner != PROGRAM_ID:
            raise RuntimeError(
                "Registry config owner mismatch"
            )

        config_raw = config_info.value.data

        expected_config_disc = account_discriminator(
            "RegistryConfig"
        )

        if config_raw[:8] != expected_config_disc:
            raise RuntimeError(
                "RegistryConfig discriminator mismatch"
            )

        stored_tuc = Pubkey.from_bytes(
            config_raw[8:40]
        )

        stored_nsp = Pubkey.from_bytes(
            config_raw[40:72]
        )

        if stored_tuc != TUC_AUTHORITY:
            raise RuntimeError(
                "On-chain TUC authority mismatch"
            )

        if stored_nsp != NSP_AUTHORITY:
            raise RuntimeError(
                "On-chain NSP authority mismatch"
            )

        print("Registry config: VERIFIED")







        existing = await client.get_account_info(
            smd_pda
        )

        if existing.value is not None:

            print(
                "SMD PDA already exists; verifying existing record."
            )

            if existing.value.owner != PROGRAM_ID:
                raise RuntimeError(
                    "Existing SMD account has wrong owner"
                )

            decoded = decode_smd_record(
                existing.value.data
            )

            if decoded["eid_hash"] != eid_hash:
                raise RuntimeError(
                    "Existing EID hash mismatch"
                )

            if decoded["eid_smd"] != eid_smd:
                raise RuntimeError(
                    "Existing EID_SMD mismatch"
                )

            if decoded["pk_smd"] != pk_compressed:
                raise RuntimeError(
                    "Existing PK_SMD mismatch"
                )

            if decoded["a_smd"] != a_compressed:
                raise RuntimeError(
                    "Existing A_SMD mismatch"
                )

            if decoded["rs_smd"] != 0:
                raise RuntimeError(
                    "Existing SMD is already revoked"
                )

            finalize_local(
                pending,
                eid_hash,
                smd_pda,
                None,
            )

            print()
            print("STATUS: EXISTING SMD RECORD VERIFIED")
            return












        instruction_data = (
            instruction_discriminator(
                "insert_smd"
            )
            + eid_hash
            + borsh_string(eid_smd)
            + borsh_vec_u8(pk_compressed)
            + borsh_vec_u8(a_compressed)
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
                TUC_AUTHORITY,
                is_signer=True,
                is_writable=True,
            ),


            AccountMeta(
                SYSTEM_PROGRAM,
                is_signer=False,
                is_writable=False,
            ),
        ]

        ix = Instruction(
            PROGRAM_ID,
            instruction_data,
            accounts,
        )

        latest = await client.get_latest_blockhash()

        msg = MessageV0.try_compile(
            payer=TUC_AUTHORITY,
            instructions=[ix],
            address_lookup_table_accounts=[],
            recent_blockhash=latest.value.blockhash,
        )

        fee_resp = await client.get_fee_for_message(
            msg
        )

        print(
            "Transaction fee:",
            fee_resp.value,
            "lamports"
        )

        balance = await client.get_balance(
            TUC_AUTHORITY
        )

        print(
            "TUC balance before:",
            balance.value / 1_000_000_000,
            "SOL"
        )





        tx = VersionedTransaction(
            msg,
            [tuc_wallet],
        )

        result = await client.send_transaction(
            tx
        )

        signature = result.value

        print()
        print("Transaction submitted.")
        print("Signature:", signature)

        await client.confirm_transaction(
            signature,
            commitment="confirmed",
            last_valid_block_height=
                latest.value.last_valid_block_height,
        )

        print("Transaction confirmed.")





        verify = await client.get_account_info(
            smd_pda
        )

        if verify.value is None:
            raise RuntimeError(
                "SMD account was not created"
            )

        if verify.value.owner != PROGRAM_ID:
            raise RuntimeError(
                "SMD account owner mismatch"
            )

        decoded = decode_smd_record(
            verify.value.data
        )

        print()
        print("=== ON-CHAIN VERIFICATION ===")
        print(
            "EID hash match:",
            decoded["eid_hash"] == eid_hash
        )
        print(
            "EID_SMD match:",
            decoded["eid_smd"] == eid_smd
        )
        print(
            "PK_SMD match:",
            decoded["pk_smd"] == pk_compressed
        )
        print(
            "A_SMD match:",
            decoded["a_smd"] == a_compressed
        )
        print(
            "RS_SMD:",
            decoded["rs_smd"]
        )

        if decoded["eid_hash"] != eid_hash:
            raise RuntimeError(
                "On-chain EID hash mismatch"
            )

        if decoded["eid_smd"] != eid_smd:
            raise RuntimeError(
                "On-chain EID mismatch"
            )

        if decoded["pk_smd"] != pk_compressed:
            raise RuntimeError(
                "On-chain PK_SMD mismatch"
            )

        if decoded["a_smd"] != a_compressed:
            raise RuntimeError(
                "On-chain A_SMD mismatch"
            )

        if decoded["rs_smd"] != 0:
            raise RuntimeError(
                "Unexpected RS_SMD value"
            )





        finalize_local(
            pending,
            eid_hash,
            smd_pda,
            signature,
        )

        balance_after = await client.get_balance(
            TUC_AUTHORITY
        )

        print()
        print(
            "TUC balance after:",
            balance_after.value / 1_000_000_000,
            "SOL"
        )

        print()
        print(
            "STATUS: SMD-001 INSERTED AND VERIFIED ON DEVNET"
        )


asyncio.run(main())
