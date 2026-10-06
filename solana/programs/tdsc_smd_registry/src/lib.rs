use anchor_lang::prelude::*;



declare_id!("CiQyDY4MurDQJbHGZnLvVnP6BfdxKG9Fmu1GB2gPKrGQ");

#[program]
pub mod tdsc_smd_registry {
    use super::*;







    pub fn initialize_config(
        ctx: Context<InitializeConfig>,
        tuc_authority: Pubkey,
        nsp_authority: Pubkey,
    ) -> Result<()> {

        require_keys_eq!(
            ctx.accounts.authority.key(),
            tuc_authority,
            RegistryError::UnauthorizedTuc
        );

        let config = &mut ctx.accounts.config;

        config.tuc_authority = tuc_authority;
        config.nsp_authority = nsp_authority;

        msg!("TDSC registry configuration initialized.");
        msg!("TUC authority: {}", tuc_authority);
        msg!("NSP authority: {}", nsp_authority);

        Ok(())
    }













    pub fn insert_smd(
        ctx: Context<InsertSmd>,
        eid_hash: [u8; 32],
        eid_smd: String,
        pk_smd: Vec<u8>,
        a_smd: Vec<u8>,
    ) -> Result<()> {
        let config = &ctx.accounts.config;


        require_keys_eq!(
            ctx.accounts.authority.key(),
            config.tuc_authority,
            RegistryError::UnauthorizedTuc
        );


        require!(
            eid_smd.as_bytes().len() <= SmdRecord::MAX_EID_LEN,
            RegistryError::EidTooLong
        );



        require!(
            pk_smd.len() == SmdRecord::ECC_POINT_LEN,
            RegistryError::InvalidPublicKeyLength
        );


        require!(
            a_smd.len() == SmdRecord::ECC_POINT_LEN,
            RegistryError::InvalidPublicKeyLength
        );

        let record = &mut ctx.accounts.smd_record;

        record.eid_hash = eid_hash;
        record.eid_smd = eid_smd;
        record.pk_smd = pk_smd;
        record.a_smd = a_smd;





        record.rs_smd = 0;

        msg!("SMD record inserted.");
        msg!("RS_SMD = 0");

        Ok(())
    }













    pub fn revoke_smd(
        ctx: Context<RevokeSmd>,
    ) -> Result<()> {
        let signer = ctx.accounts.authority.key();

        let tuc = ctx.accounts.config.tuc_authority;
        let nsp = ctx.accounts.config.nsp_authority;


        require!(
            signer == tuc || signer == nsp,
            RegistryError::UnauthorizedRevocation
        );

        let record = &mut ctx.accounts.smd_record;

        record.rs_smd = 1;

        msg!("SMD revoked.");
        msg!("RS_SMD = 1");

        Ok(())
    }
}






#[derive(Accounts)]
pub struct InitializeConfig<'info> {

    #[account(
        init,
        payer = authority,
        space = RegistryConfig::SPACE,
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,


    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}






#[derive(Accounts)]
#[instruction(eid_hash: [u8; 32])]
pub struct InsertSmd<'info> {

    #[account(
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,






    #[account(
        init,
        payer = authority,
        space = SmdRecord::SPACE,
        seeds = [
            b"smd",
            eid_hash.as_ref()
        ],
        bump
    )]
    pub smd_record: Account<'info, SmdRecord>,


    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}






#[derive(Accounts)]
pub struct RevokeSmd<'info> {

    #[account(
        seeds = [b"config"],
        bump
    )]
    pub config: Account<'info, RegistryConfig>,


    #[account(mut)]
    pub smd_record: Account<'info, SmdRecord>,


    pub authority: Signer<'info>,
}








#[account]
pub struct RegistryConfig {

    pub tuc_authority: Pubkey,


    pub nsp_authority: Pubkey,
}

impl RegistryConfig {



    pub const SPACE: usize =
        8 +
        32 +
        32;
}










#[account]
pub struct SmdRecord {



    pub eid_hash: [u8; 32],


    pub eid_smd: String,





    pub pk_smd: Vec<u8>,





    pub a_smd: Vec<u8>,





    pub rs_smd: u8,
}

impl SmdRecord {

    pub const MAX_EID_LEN: usize = 256;


    pub const ECC_POINT_LEN: usize = 33;











    pub const SPACE: usize =
        8 +
        32 +
        4 + Self::MAX_EID_LEN +
        4 + Self::ECC_POINT_LEN +
        4 + Self::ECC_POINT_LEN +
        1;
}






#[error_code]
pub enum RegistryError {
    #[msg("Only the registered TUC can perform this operation.")]
    UnauthorizedTuc,

    #[msg("Only the registered TUC or NSP can revoke an SMD.")]
    UnauthorizedRevocation,

    #[msg("EID_SMD is too long.")]
    EidTooLong,

    #[msg("ECC public point must be a 33-byte compressed SEC1 point.")]
    InvalidPublicKeyLength,
}