from pathlib import Path
import asyncio
import hashlib

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

TUC_WALLET_PATH = Path("tuc/data/solana_tuc.key")

TUC_AUTHORITY = Pubkey.from_string(
    "CQSBRzGMFdjfTx3Nqaue31N4HEuLeuTUDmJLk9QVN4E2"
)

NSP_AUTHORITY = Pubkey.from_string(
    "Gd5nHLBUVkdDxKuBVbXUtbTk9s3ZCaztMAn6b9btfPou"
)

SYSTEM_PROGRAM = Pubkey.from_string(
    "11111111111111111111111111111111"
)


def instruction_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"global:{name}".encode()
    ).digest()[:8]


def account_discriminator(name: str) -> bytes:
    return hashlib.sha256(
        f"account:{name}".encode()
    ).digest()[:8]


async def main():




    tuc_wallet = Keypair.from_bytes(
        TUC_WALLET_PATH.read_bytes()
    )

    if tuc_wallet.pubkey() != TUC_AUTHORITY:
        raise RuntimeError(
            "TUC wallet does not match configured authority"
        )






    config_pda, config_bump = Pubkey.find_program_address(
        [b"config"],
        PROGRAM_ID
    )

    print("Program ID:", PROGRAM_ID)
    print("TUC authority:", TUC_AUTHORITY)
    print("NSP authority:", NSP_AUTHORITY)
    print("Config PDA:", config_pda)
    print("Config bump:", config_bump)
    print()

    async with AsyncClient(RPC) as client:





        current = await client.get_account_info(config_pda)

        if current.value is not None:
            print("Config PDA already exists.")

            data = current.value.data

            expected_disc = account_discriminator(
                "RegistryConfig"
            )

            if data[:8] != expected_disc:
                raise RuntimeError(
                    "Existing account has unexpected discriminator"
                )

            existing_tuc = Pubkey.from_bytes(
                data[8:40]
            )

            existing_nsp = Pubkey.from_bytes(
                data[40:72]
            )

            print("Stored TUC:", existing_tuc)
            print("Stored NSP:", existing_nsp)

            if (
                existing_tuc == TUC_AUTHORITY
                and existing_nsp == NSP_AUTHORITY
            ):
                print(
                    "STATUS: REGISTRY CONFIG ALREADY CORRECT"
                )
                return

            raise RuntimeError(
                "Config already exists with different authorities"
            )











        data = (
            instruction_discriminator(
                "initialize_config"
            )
            + bytes(TUC_AUTHORITY)
            + bytes(NSP_AUTHORITY)
        )

        accounts = [

            AccountMeta(
                config_pda,
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
            data,
            accounts,
        )




        latest = await client.get_latest_blockhash()

        msg = MessageV0.try_compile(
            payer=TUC_AUTHORITY,
            instructions=[ix],
            address_lookup_table_accounts=[],
            recent_blockhash=latest.value.blockhash,
        )

        fee_resp = await client.get_fee_for_message(msg)

        if fee_resp.value is None:
            raise RuntimeError(
                "Unable to calculate transaction fee"
            )

        print(
            "Estimated transaction fee:",
            fee_resp.value,
            "lamports"
        )

        balance = await client.get_balance(
            TUC_AUTHORITY
        )

        print(
            "TUC balance:",
            balance.value / 1_000_000_000,
            "SOL"
        )




        tx = VersionedTransaction(
            msg,
            [tuc_wallet]
        )

        result = await client.send_transaction(tx)

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
            config_pda
        )

        if verify.value is None:
            raise RuntimeError(
                "Config account was not created"
            )

        if verify.value.owner != PROGRAM_ID:
            raise RuntimeError(
                "Config account has wrong owner"
            )

        raw = verify.value.data

        expected_disc = account_discriminator(
            "RegistryConfig"
        )

        if raw[:8] != expected_disc:
            raise RuntimeError(
                "RegistryConfig discriminator mismatch"
            )

        stored_tuc = Pubkey.from_bytes(
            raw[8:40]
        )

        stored_nsp = Pubkey.from_bytes(
            raw[40:72]
        )

        print()
        print("Stored TUC:", stored_tuc)
        print("Stored NSP:", stored_nsp)

        if stored_tuc != TUC_AUTHORITY:
            raise RuntimeError(
                "Stored TUC authority mismatch"
            )

        if stored_nsp != NSP_AUTHORITY:
            raise RuntimeError(
                "Stored NSP authority mismatch"
            )

        print()
        print(
            "STATUS: REGISTRY CONFIG INITIALIZED AND VERIFIED"
        )


asyncio.run(main())
