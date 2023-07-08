// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import {INonceManager} from "./INonceManager.sol";
import {IIntentStandard} from "./IIntentStandard.sol";
import {UserIntent} from "./UserIntent.sol";

interface IEntryPoint is INonceManager {
    /**
     *
     * An event emitted after each successful intent solution
     * @param userIntHash - unique identifier for the intent (hash its entire content, except signature).
     * @param sender - the account that generates this intent.
     * @param submitter - the account that submitted the solution for the intent.
     * @param nonce - the nonce value from the intent.
     */
    event UserIntentEvent(
        bytes32 indexed userIntHash, address indexed sender, address indexed submitter, uint256 nonce
    );

    /**
     * An event emitted if the UserIntent "callData" reverted with non-zero length
     * @param userIntHash the intent unique identifier.
     * @param sender the sender of this intent.
     * @param nonce the nonce used in the intent.
     * @param revertReason - the return bytes from the (reverted) call to "callData".
     */
    event UserIntentRevertReason(
        bytes32 indexed userIntHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    /**
     * An event emitted if the UserIntent "callData" reverted with non-zero length
     * @param stepIndex the index of the solution step.
     * @param target the solution step target.
     * @param revertReason - the return bytes from the (reverted) call to "callData".
     */
    event SolutionRevertReason(uint256 stepIndex, address target, bytes revertReason);

    /**
     * an event emitted by handleInts(), before starting the execution loop.
     * any event emitted before this event, is part of the validation.
     */
    event BeforeExecution();

    /**
     * a custom revert error of handleInts, to identify the offending solution and intent.
     *  NOTE: if simulateValidation passes successfully, there should be no reason for handleInts to fail on it.
     *  @param solIndex - index into the array of solutions to the failed one (in simulateValidation, this is always zero)
     *  @param intIndex - index into the array of intents to the failed one
     *  @param reason - revert reason
     *      The string starts with a unique code "AAmn", where "m" is "1" for solution, "2" for intent issues,
     *      so a failure can be attributed to the correct entity.
     *   Should be caught in off-chain handleInts simulation and not happen on-chain.
     *   Useful for mitigating DoS attempts against solvers or for troubleshooting of solution/intent reverts.
     */
    error FailedInt(uint256 solIndex, uint256 intIndex, string reason);

    /**
     * Successful result from simulateValidation.
     * @param sigFailed - UserIntent signature check failed
     * @param validAfter - first timestamp this UserIntent is valid
     * @param validUntil - last timestamp this UserIntent is valid
     */
    error ValidationResult(bool sigFailed, uint48 validAfter, uint48 validUntil);

    /**
     * return value of simulateHandleInt
     */
    error ExecutionResult(uint48 validAfter, uint48 validUntil, bool targetSuccess, bytes targetResult);

    //UserInts handled, per solution
    struct IntentSolution {
        UserIntent[] userInts;
        SolutionStep[] steps1;
        SolutionStep[] steps2;
    }

    struct SolutionStep {
        address target;
        uint256 value;
        bytes callData;
    }

    /**
     * Execute a batch of UserIntents with given solutions.
     * @param solutions the solutions to intents to execute
     */
    function handleInts(IntentSolution[] calldata solutions) external;

    /**
     * simulate full execution of a UserIntent solution (including both validation and target execution)
     * this method will always revert with "ExecutionResult".
     * it performs full validation of the UserIntent solution, but ignores signature error.
     * an optional target address is called after the solution succeeds, and its value is returned
     * (before the entire call is reverted)
     * Note that in order to collect the the success/failure of the target call, it must be executed
     * with trace enabled to track the emitted events.
     * @param solution the UserIntent solution to simulate
     * @param timestamp the timestamp at which to evaluate the intents
     * @param target if nonzero, a target address to call after user intent simulation. If called,
     *        the targetSuccess and targetResult are set to the return from that call.
     * @param targetCallData callData to pass to target address
     */
    function simulateHandleInt(
        IntentSolution calldata solution,
        uint256 timestamp,
        address target,
        bytes calldata targetCallData
    ) external;

    /**
     * Simulate a call to account.validateUserInt.
     * @dev this method always revert. Successful result is ValidationResult error. other errors are failures.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage outside the account's data.
     * @param userInt the user intent to validate.
     */
    function simulateValidation(UserIntent calldata userInt) external;

    /**
     * generate an intent Id - unique identifier for this intent.
     * the intent ID is a hash over the content of the userInt (except the signature), the entrypoint and the chainid.
     */
    function getUserIntHash(UserIntent calldata userInt) external view returns (bytes32);

    /**
     * registers a new intent standard.
     */
    function registerIntentStandard(IIntentStandard standardContract) external returns (bytes32);

    /**
     * gets the intent contract for the given standard (address(0) if unknown).
     */
    function getIntentStandardContract(bytes32 standardId) external view returns (IIntentStandard);

    /**
     * returns if intent validation actions are currently being executed.
     */
    function validationExecuting() external view returns (bool);

    /**
     * returns if intent specific actions are currently being executed.
     */
    function intentExecuting() external view returns (bool);

    /**
     * returns if intent solution specific actions are currently being executed.
     */
    function solutionExecuting() external view returns (bool);
}