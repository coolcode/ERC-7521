// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

/* solhint-disable func-name-mixedcase */
/* solhint-disable const-name-snakecase */

import "forge-std/Test.sol";
import {IntentBuilder} from "./IntentBuilder.sol";
import {EntryPoint} from "../../../src/core/EntryPoint.sol";
import {UserIntent} from "../../../src/interfaces/UserIntent.sol";
import {IntentSolution} from "../../../src/interfaces/IntentSolution.sol";
import {encodeErc20RecordData} from "../../../src/standards/Erc20Record.sol";
import {ERC20_RECORD_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeErc20ReleaseData, encodeErc20ReleaseComplexData} from "../../../src/standards/Erc20Release.sol";
import {ERC20_RELEASE_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeErc20RequireData, encodeErc20RequireComplexData} from "../../../src/standards/Erc20Require.sol";
import {ERC20_REQUIRE_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeEthRecordData} from "../../../src/standards/EthRecord.sol";
import {ETH_RECORD_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeEthReleaseData, encodeEthReleaseComplexData} from "../../../src/standards/EthRelease.sol";
import {ETH_RELEASE_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeEthRequireData, encodeEthRequireComplexData} from "../../../src/standards/EthRequire.sol";
import {ETH_REQUIRE_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeSequentialNonceData} from "../../../src/standards/SequentialNonce.sol";
import {SEQUENTIAL_NONCE_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeSimpleCallData} from "../../../src/standards/SimpleCall.sol";
import {SIMPLE_CALL_STD_ID} from "../../../src/core/EntryPoint.sol";
import {encodeUserOperationData} from "../../../src/standards/UserOperation.sol";
import {USER_OPERATION_STD_ID} from "../../../src/core/EntryPoint.sol";
import {TestERC20} from "../../../src/test/TestERC20.sol";
import {TestUniswap} from "../../../src/test/TestUniswap.sol";
import {TestWrappedNativeToken} from "../../../src/test/TestWrappedNativeToken.sol";
import {SolverUtils} from "../../../src/test/SolverUtils.sol";
import {SimpleAccountFactory} from "../../../src/samples/SimpleAccountFactory.sol";
import {SimpleAccount} from "../../../src/samples/SimpleAccount.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

abstract contract ScenarioTestEnvironment is Test {
    using IntentBuilder for UserIntent;
    using ECDSA for bytes32;

    //main contracts
    EntryPoint internal _entryPoint;
    SimpleAccount internal _account;

    //testing contracts
    TestERC20 internal _testERC20;
    TestUniswap internal _testUniswap;
    TestWrappedNativeToken internal _testWrappedNativeToken;
    SolverUtils internal _solverUtils;
    address internal _token;

    //keys
    uint256 internal constant _privateKey = uint256(keccak256("account_private_key"));
    address internal _publicAddress = _getPublicAddress(_privateKey);

    uint256 internal constant _privateKeySolver = uint256(keccak256("solver_private_key"));
    address internal _publicAddressSolver = _getPublicAddress(_privateKeySolver);

    uint256 internal constant _wrong_private_key = uint256(keccak256("wrong_account_private_key"));
    address internal _wrongPublicAddress = _getPublicAddress(_wrong_private_key);

    /**
     * Sets up the testing environment with mock tokens and AMMs.
     */
    function setUp() public virtual {
        //deploy contracts
        _entryPoint = new EntryPoint();

        //deploy accounts
        SimpleAccountFactory accountFactory = new SimpleAccountFactory(_entryPoint);
        _account = accountFactory.createAccount(_publicAddress, 0);

        //deploy test contracts
        _testERC20 = new TestERC20();
        _testWrappedNativeToken = new TestWrappedNativeToken();
        _testUniswap = new TestUniswap(_testWrappedNativeToken);
        _solverUtils = new SolverUtils(_testUniswap, _testERC20, _testWrappedNativeToken);
        _token = address(_testERC20);

        //fund exchange
        _testERC20.mint(address(_testUniswap), 1000 ether);
        _mintWrappedNativeToken(address(_testUniswap), 1000 ether);
    }

    /**
     * Private helper function to quickly mint wrapped native tokens.
     * @param to The address to receive the minted tokens.
     * @param amount The amount of tokens to mint.
     */
    function _mintWrappedNativeToken(address to, uint256 amount) internal {
        vm.deal(address(this), amount);
        _testWrappedNativeToken.deposit{value: amount}();
        _testWrappedNativeToken.transfer(to, amount);
    }

    /**
     * Private helper function to build call data for the account claiming an ERC20 airdrop.
     * @param amount The amount of ERC20 tokens to claim in the airdrop.
     * @return The encoded call data for the claim airdrop action.
     */
    function _accountClaimAirdropERC20(uint256 amount) internal view returns (bytes memory) {
        bytes memory mintCall = abi.encodeWithSelector(TestERC20.mint.selector, address(_account), amount);
        return abi.encodeWithSelector(SimpleAccount.execute.selector, _testERC20, 0, mintCall);
    }

    /**
     * Private helper function to build call data for the solver to swap tokens and forward some ETH.
     * @param minETH The minimum amount of ETH to be received after the swap.
     * @param to The address to receive the swapped ETH.
     * @param forwardAmount The amount of ETH to forward to another address.
     * @param forwardTo The address to forward the ETH to.
     * @return The encoded call data for the swap and forward action.
     */
    function _solverSwapERC20ForETHAndForward(uint256 minETH, address to, uint256 forwardAmount, address forwardTo)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            SolverUtils.swapERC20ForETHAndForward.selector,
            _testUniswap,
            _testERC20,
            _testWrappedNativeToken,
            minETH,
            to,
            forwardAmount,
            forwardTo
        );
    }

    /**
     * Private helper function to build call data for the solver to transfer the test ERC20 token.
     * @param recipient The token recipient.
     * @param amount The amount of tokens to transfer.
     * @return The encoded call data for the transfer action.
     */
    function _solverTransferERC20(address recipient, uint256 amount) internal view returns (bytes memory) {
        return abi.encodeWithSelector(SolverUtils.transferERC20.selector, _testERC20, recipient, amount);
    }

    /**
     * Private helper function to build call data for the solver to transfer ETH.
     * @param recipient The token recipient.
     * @param amount The amount of ETH to transfer.
     * @return The encoded call data for the transfer action.
     */
    function _solverTransferETH(address recipient, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SolverUtils.transferETH.selector, recipient, amount);
    }

    /**
     * Private helper function to build a call intent struct for the solver.
     * @return The created UserIntent struct.
     */
    function _solverIntent() internal view returns (UserIntent memory) {
        return IntentBuilder.create(address(_solverUtils));
    }

    /**
     * Private helper function to build a user intent struct.
     * @return The created UserIntent struct.
     */
    function _intent() internal view returns (UserIntent memory) {
        return IntentBuilder.create(address(_account));
    }

    function _addErc20Record(UserIntent memory intent, bool isProxy) internal view returns (UserIntent memory) {
        return intent.addSegment(encodeErc20RecordData(ERC20_RECORD_STD_ID, _token, isProxy));
    }

    function _addErc20Release(UserIntent memory intent, int256 amount, bool isProxy)
        internal
        view
        returns (UserIntent memory)
    {
        return intent.addSegment(encodeErc20ReleaseData(ERC20_RELEASE_STD_ID, _token, amount, isProxy));
    }

    function _addErc20ReleaseLinear(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        bool isProxy
    ) internal view returns (UserIntent memory) {
        return intent.addSegment(
            encodeErc20ReleaseComplexData(
                ERC20_RELEASE_STD_ID, _token, startTime, deltaTime, startAmount, deltaAmount, 1, false, isProxy
            )
        );
    }

    function _addErc20ReleaseExponential(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        uint8 exponent,
        bool backwards,
        bool isProxy
    ) internal view returns (UserIntent memory) {
        return intent.addSegment(
            encodeErc20ReleaseComplexData(
                ERC20_RELEASE_STD_ID,
                _token,
                startTime,
                deltaTime,
                startAmount,
                deltaAmount,
                exponent,
                backwards,
                isProxy
            )
        );
    }

    function _addErc20Require(UserIntent memory intent, int256 amount, bool isRelative, bool isProxy)
        internal
        view
        returns (UserIntent memory)
    {
        return intent.addSegment(encodeErc20RequireData(ERC20_REQUIRE_STD_ID, _token, amount, isRelative, isProxy));
    }

    function _addErc20RequireLinear(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        bool isRelative,
        bool isProxy
    ) internal view returns (UserIntent memory) {
        return intent.addSegment(
            encodeErc20RequireComplexData(
                ERC20_REQUIRE_STD_ID,
                _token,
                startTime,
                deltaTime,
                startAmount,
                deltaAmount,
                1,
                false,
                isRelative,
                isProxy
            )
        );
    }

    function _addErc20RequireExponential(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        uint8 exponent,
        bool backwards,
        bool isRelative,
        bool isProxy
    ) internal view returns (UserIntent memory) {
        return intent.addSegment(
            encodeErc20RequireComplexData(
                ERC20_REQUIRE_STD_ID,
                _token,
                startTime,
                deltaTime,
                startAmount,
                deltaAmount,
                exponent,
                backwards,
                isRelative,
                isProxy
            )
        );
    }

    function _addEthRecord(UserIntent memory intent, bool isProxy) internal pure returns (UserIntent memory) {
        return intent.addSegment(encodeEthRecordData(ETH_RECORD_STD_ID, isProxy));
    }

    function _addEthRelease(UserIntent memory intent, int256 amount) internal pure returns (UserIntent memory) {
        return intent.addSegment(encodeEthReleaseData(ETH_RELEASE_STD_ID, amount));
    }

    function _addEthReleaseLinear(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount
    ) internal pure returns (UserIntent memory) {
        return intent.addSegment(
            encodeEthReleaseComplexData(ETH_RELEASE_STD_ID, startTime, deltaTime, startAmount, deltaAmount, 1, false)
        );
    }

    function _addEthReleaseExponential(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        uint8 exponent,
        bool backwards
    ) internal pure returns (UserIntent memory) {
        return intent.addSegment(
            encodeEthReleaseComplexData(
                ETH_RELEASE_STD_ID, startTime, deltaTime, startAmount, deltaAmount, exponent, backwards
            )
        );
    }

    function _addEthRequire(UserIntent memory intent, int256 amount, bool isRelative, bool isProxy)
        internal
        pure
        returns (UserIntent memory)
    {
        return intent.addSegment(encodeEthRequireData(ETH_REQUIRE_STD_ID, amount, isRelative, isProxy));
    }

    function _addEthRequireLinear(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        bool isRelative,
        bool isProxy
    ) internal pure returns (UserIntent memory) {
        return intent.addSegment(
            encodeEthRequireComplexData(
                ETH_REQUIRE_STD_ID, startTime, deltaTime, startAmount, deltaAmount, 1, false, isRelative, isProxy
            )
        );
    }

    function _addEthRequireExponential(
        UserIntent memory intent,
        uint32 startTime,
        uint16 deltaTime,
        int256 startAmount,
        int256 deltaAmount,
        uint8 exponent,
        bool backwards,
        bool isRelative,
        bool isProxy
    ) internal pure returns (UserIntent memory) {
        return intent.addSegment(
            encodeEthRequireComplexData(
                ETH_REQUIRE_STD_ID,
                startTime,
                deltaTime,
                startAmount,
                deltaAmount,
                exponent,
                backwards,
                isRelative,
                isProxy
            )
        );
    }

    function _addSequentialNonce(UserIntent memory intent, uint256 nonce) internal pure returns (UserIntent memory) {
        return intent.addSegment(encodeSequentialNonceData(SEQUENTIAL_NONCE_STD_ID, nonce));
    }

    function _addSimpleCall(UserIntent memory intent, bytes memory callData)
        internal
        pure
        returns (UserIntent memory)
    {
        return intent.addSegment(encodeSimpleCallData(SIMPLE_CALL_STD_ID, callData));
    }

    function _addUserOp(UserIntent memory intent, uint32 callGasLimit, bytes memory callData)
        internal
        pure
        returns (UserIntent memory)
    {
        return intent.addSegment(encodeUserOperationData(USER_OPERATION_STD_ID, callGasLimit, callData));
    }

    /**
     * Private helper function to build an intent solution struct.
     * @param intent1 First intent that's part of the solution.
     * @param intent2 Second intent that's part of the solution.
     * @return The created IntentSolution struct.
     */
    function _solution(UserIntent memory intent1, UserIntent memory intent2)
        internal
        view
        returns (IntentSolution memory)
    {
        UserIntent[] memory intents = new UserIntent[](2);
        intents[0] = intent1;
        intents[1] = intent2;

        uint256 len1 = intent1.intentData.length;
        uint256 len2 = intent2.intentData.length;
        uint256[] memory order = new uint256[](len1 + len2);
        uint256 index = 0;
        while (len1 > 0 || len2 > 0) {
            if (len1 > 0) {
                order[index] = 0;
                len1--;
                index++;
            }
            if (len2 > 0) {
                order[index] = 1;
                len2--;
                index++;
            }
        }

        return IntentSolution({timestamp: block.timestamp, intents: intents, order: order});
    }

    /**
     * Private helper function to build an intent solution struct.
     * @param intent1 First intent that's part of the solution.
     * @param intent2 Second intent that's part of the solution.
     * @param order The order of intents to execute.
     * @return The created IntentSolution struct.
     */
    function _solution(UserIntent memory intent1, UserIntent memory intent2, uint256[] memory order)
        internal
        view
        returns (IntentSolution memory)
    {
        UserIntent[] memory intents = new UserIntent[](2);
        intents[0] = intent1;
        intents[1] = intent2;
        return IntentSolution({timestamp: block.timestamp, intents: intents, order: order});
    }

    /**
     * Private helper function to build an intent solution struct.
     * @return The created IntentSolution struct.
     */
    function _emptySolution() internal view returns (IntentSolution memory) {
        UserIntent[] memory intents = new UserIntent[](0);
        uint256[] memory order = new uint256[](0);
        return IntentSolution({timestamp: block.timestamp, intents: intents, order: order});
    }

    /**
     * Private helper function to build an intent solution struct with a single intent.
     * @param intent Intent to include in the solution.
     * @return The created IntentSolution struct.
     */
    function _singleIntentSolution(UserIntent memory intent) internal view returns (IntentSolution memory) {
        UserIntent[] memory intents = new UserIntent[](1);
        intents[0] = intent;
        uint256[] memory order = new uint256[](0);
        return IntentSolution({timestamp: block.timestamp, intents: intents, order: order});
    }

    /**
     * Private helper function to turn a single intent struct into an array.
     * @param intent The intent to turn into an array.
     * @return The created intent array.
     */
    function _singleIntent(UserIntent memory intent) internal pure returns (UserIntent[] memory) {
        UserIntent[] memory intents = new UserIntent[](1);
        intents[0] = intent;
        return intents;
    }

    /**
     * Private helper function to add the account owner's signature to an intent.
     * @param intent The UserIntent struct representing the user's intent.
     * @return The UserIntent struct with the added signature.
     */
    function _signIntent(UserIntent memory intent) internal view returns (UserIntent memory) {
        bytes32 intentHash = _entryPoint.getUserIntentHash(intent);
        bytes32 digest = intentHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_privateKey, digest);
        intent.signature = abi.encodePacked(r, s, v);
        return intent;
    }

    /**
     * Private helper function to add an invalid signature to an intent.
     * @param intent The UserIntent struct representing the user's intent.
     * @return The UserIntent struct with the added signature.
     */
    function _signIntentWithWrongKey(UserIntent memory intent) internal view returns (UserIntent memory) {
        bytes32 intentHash = _entryPoint.getUserIntentHash(intent);
        bytes32 digest = intentHash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_wrong_private_key, digest);
        intent.signature = abi.encodePacked(r, s, v);
        return intent;
    }

    /**
     * Private helper function to get the public address of a private key.
     * @param privateKey The private key to derive the public address from.
     * @return The derived public address.
     */
    function _getPublicAddress(uint256 privateKey) internal pure returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("test data"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return ecrecover(digest, v, r, s);
    }

    /**
     * Private helper function to get bytes (usefule for analyzing segment data).
     * @param data The data to pull from.
     * @param from The start index.
     * @param to The end index.
     * @return result the bytes.
     */
    function _getBytes(bytes memory data, uint256 from, uint256 to) internal pure returns (bytes32 result) {
        result = bytes32(0);
        for (uint256 i = from; i < to; i++) {
            result = (result << 8) | (bytes32(data[i]) >> (31 * 8));
        }
        result = result << ((32 - (to - from)) * 8);
    }

    /**
     * Add a test to exclude this contract from coverage report
     * note: there is currently an open ticket to resolve this more gracefully
     * https://github.com/foundry-rs/foundry/issues/2988
     */
    function test() public {}
}
