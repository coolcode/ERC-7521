use ethers::{prelude::*, utils::parse_ether};
use utils::{
    builders::curve_type::{
        ConstantCurveParameters, CurveParameters, ExponentialCurveParameters, LinearCurveParameters,
    },
    setup::PROVIDER,
};

mod transfer_eth {
    use super::*;
    use scenarios::transfer_eth::transfer_eth_scenario;

    #[tokio::test]
    async fn transfer_eth() {
        // block number to evaluate the curves at
        let block_number: U256 =
            std::cmp::max(1, PROVIDER.get_block_number().await.unwrap().as_u64()).into();

        // constant eth transfer curve parameters
        let transfer_amount = parse_ether(0.1).unwrap();

        // linear erc20 release curve parameters
        let m = I256::from_raw(parse_ether(0.01 / 3.0).unwrap());
        let b = I256::from_raw(parse_ether(0).unwrap());
        let max = I256::from(3000);
        let release_parameters: CurveParameters =
            CurveParameters::Linear(LinearCurveParameters::new(m, b, max));

        // evaluate release at block number
        let release_evaluation: U256 = release_parameters.evaluate(block_number).into_raw();

        // run the scenario
        let balances = transfer_eth_scenario(
            release_parameters,
            transfer_amount,
            block_number,
            release_evaluation,
        )
        .await;

        // calculate expected balances
        let expected_solver_eth_balance =
            balances.solver.eth.initial.unwrap() + release_evaluation + 5;
        let expected_user_eth_balance = balances.user.eth.initial.unwrap() - transfer_amount;
        let expected_user_erc20_balance = balances.user.erc20.initial.unwrap() - release_evaluation;
        let expected_recipient_balance = balances.recipient.eth.initial.unwrap() + transfer_amount;

        // assert balances
        assert_eq!(
            balances.solver.eth.r#final.unwrap(),
            expected_solver_eth_balance,
            "The solver ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.eth.r#final.unwrap(),
            expected_user_eth_balance,
            "The user ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.erc20.r#final.unwrap(),
            expected_user_erc20_balance,
            "The user released more ERC20 tokens than expected"
        );
        assert_eq!(
            balances.recipient.eth.r#final.unwrap(),
            expected_recipient_balance,
            "The recipient ended up with incorrect balance"
        );
    }
}

mod transfer_erc20 {
    use super::*;
    use scenarios::transfer_erc20::transfer_erc20_scenario;

    #[tokio::test]
    async fn transfer_erc20() {
        // block number to evaluate the curves at
        let block_number: U256 =
            std::cmp::max(1, PROVIDER.get_block_number().await.unwrap().as_u64()).into();

        // constant erc20 transfer curve parameters
        let transfer_amount = parse_ether(0.1).unwrap();

        // linear erc20 release curve parameters
        let m = I256::from_raw(parse_ether(0.01 / 3.0).unwrap());
        let b = I256::from_raw(parse_ether(0).unwrap());
        let max = I256::from(3000);
        let release_parameters: CurveParameters =
            CurveParameters::Linear(LinearCurveParameters::new(m, b, max));

        // linear erc20 require curve parameters
        let m = I256::from_raw(parse_ether(0.01 / 3.0).unwrap());
        let b = I256::from_raw(parse_ether(0).unwrap());
        let max = I256::from(-3000);
        let require_parameters: CurveParameters =
            CurveParameters::Linear(LinearCurveParameters::new(m, b, max));

        // evaluate release at block number
        let release_evaluation: U256 = release_parameters.evaluate(block_number).into_raw();

        // run the scenario
        let balances = transfer_erc20_scenario(
            release_parameters,
            require_parameters,
            transfer_amount,
            block_number,
            release_evaluation,
        )
        .await;

        // calculate expected balances
        let expected_solver_eth_balance =
            balances.solver.eth.initial.unwrap() + release_evaluation + 5;
        let expected_user_erc20_balance =
            balances.user.erc20.initial.unwrap() - release_evaluation - transfer_amount;
        let expected_recipient_erc20_balance =
            balances.recipient.erc20.initial.unwrap() + transfer_amount;

        // assert balances
        assert_eq!(
            balances.solver.eth.r#final.unwrap(),
            expected_solver_eth_balance,
            "The solver ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.erc20.r#final.unwrap(),
            expected_user_erc20_balance,
            "The user released more ERC20 tokens than expected"
        );
        assert_eq!(
            balances.recipient.erc20.r#final.unwrap(),
            expected_recipient_erc20_balance,
            "The recipient ended up with incorrect ERC20 balance"
        );
    }
}

mod token_swap {
    use super::*;
    use scenarios::token_swaps::token_swap_scenario;

    #[tokio::test]
    async fn constant_release() {
        // block number to evaluate the curves at
        let block_number: U256 =
            std::cmp::max(1, PROVIDER.get_block_number().await.unwrap().as_u64()).into();

        // constant erc20 release curve parameters
        let release_amount = parse_ether(10).unwrap();
        let release_parameters: CurveParameters =
            CurveParameters::Constant(ConstantCurveParameters::new(I256::from_raw(release_amount)));

        // linear eth require curve parameters
        let m = I256::from_raw(parse_ether(0.01).unwrap());
        let b = I256::from_raw(parse_ether(7).unwrap());
        let max = I256::from(100);
        let require_parameters: CurveParameters =
            CurveParameters::Linear(LinearCurveParameters::new(m, b, max));

        // evaluate requirement at block number
        let require_evaluation: U256 = require_parameters.evaluate(block_number).into_raw();

        // run the scenario
        let balances = token_swap_scenario(
            release_parameters,
            require_parameters,
            block_number,
            release_amount,
            require_evaluation,
        )
        .await;

        // calculate expected balances
        let expected_solver_eth_balance =
            balances.solver.eth.initial.unwrap() + release_amount - require_evaluation + 5;
        let expected_user_eth_balance = balances.user.eth.initial.unwrap() + require_evaluation;
        let expected_user_erc20_balance = balances.user.erc20.initial.unwrap() - release_amount;

        // assert balances
        assert_eq!(
            balances.solver.eth.r#final.unwrap(),
            expected_solver_eth_balance,
            "The solver ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.eth.r#final.unwrap(),
            expected_user_eth_balance,
            "The user ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.erc20.r#final.unwrap(),
            expected_user_erc20_balance,
            "The user released more ERC20 tokens than expected"
        );
    }

    #[tokio::test]
    async fn constant_expectation() {
        // block number to evaluate the curves at
        let block_number: U256 =
            std::cmp::max(1, PROVIDER.get_block_number().await.unwrap().as_u64()).into();

        // linear erc20 release curve parameters
        let m = I256::from_raw(parse_ether(0.000075).unwrap());
        let b = I256::from_raw(parse_ether(7).unwrap());
        let e = I256::from(2);
        let max = I256::from(100);
        let release_parameters: CurveParameters =
            CurveParameters::Exponential(ExponentialCurveParameters::new(m, b, e, max));

        // evaluate release at block number
        let release_evaluation: U256 = release_parameters.evaluate(block_number).into_raw();

        // constant eth require curve parameters
        let require_amount = parse_ether(7).unwrap();
        let require_parameters: CurveParameters =
            CurveParameters::Constant(ConstantCurveParameters::new(I256::from_raw(require_amount)));

        // run the scenario
        let balances = token_swap_scenario(
            release_parameters,
            require_parameters,
            block_number,
            release_evaluation,
            require_amount,
        )
        .await;

        // calculate expected balances
        let expected_solver_eth_balance =
            balances.solver.eth.initial.unwrap() + release_evaluation - require_amount + 5;
        let expected_user_eth_balance = balances.user.eth.initial.unwrap() + require_amount;
        let expected_user_erc20_balance = balances.user.erc20.initial.unwrap() - release_evaluation;

        // assert balances
        assert_eq!(
            balances.solver.eth.r#final.unwrap(),
            expected_solver_eth_balance,
            "The solver ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.eth.r#final.unwrap(),
            expected_user_eth_balance,
            "The user ended up with incorrect balance"
        );
        assert_eq!(
            balances.user.erc20.r#final.unwrap(),
            expected_user_erc20_balance,
            "The user released more ERC20 tokens than expected"
        );
    }
}