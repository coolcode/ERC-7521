// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {IIntentStandardRegistry} from "./IIntentStandardRegistry.sol";
import {INonceManager} from "./INonceManager.sol";
import {IntentSolution} from "./IntentSolution.sol";
import {IIntentStandard} from "./IIntentStandard.sol";
import {IAggregator} from "./IAggregator.sol";
import {UserIntent} from "./UserIntent.sol";

interface IEntryPoint is INonceManager, IIntentStandardRegistry {
    /**
     * An event emitted after each successful intent solution
     * @param intentHash - unique identifier for the intent (hash its entire content, except signature).
     * @param sender - the account that generates this intent.
     * @param submitter - the account that submitted the solution for the intent.
     */
    event UserIntentEvent(bytes32 indexed intentHash, address indexed sender, address indexed submitter);

    /**
     * a custom revert error of handleIntents, to identify the offending intent.
     * @param intIndex - index into the array of intents to the failed one
     * @param segIndex - index into the array of intent segments to the failed one
     * @param reason - revert reason
     *  Should be caught in off-chain handleIntents simulation and not happen on-chain.
     *  Useful for mitigating DoS attempts against solvers or for troubleshooting of solution/intent reverts.
     */
    error FailedIntent(uint256 intIndex, uint256 segIndex, string reason);

    /**
     * Execute a batch of UserIntents with given solution.
     * @param solution the UserIntents solution.
     */
    function handleIntents(IntentSolution calldata solution) external;

    /**
     * Execute a batch of UserIntents using multiple solutions.
     * @param solutions list of solutions to execute for intents.
     */
    function handleIntentsMulti(IntentSolution[] calldata solutions) external;

    /**
     * Execute a batch of UserIntents with an aggregated signature.
     * @param solutions list of solutions to execute for intents.
     * @param aggregator address of aggregator.
     * @param intentsToAggregate bit field signaling which intents are part of the aggregated signature.
     * @param signature aggregated signature.
     */
    function handleIntentsAggregated(
        IntentSolution[] calldata solutions,
        IAggregator aggregator,
        bytes32 intentsToAggregate,
        bytes calldata signature
    ) external;

    /**
     * Run validation for the given intent.
     * @dev This method is view only.
     * @param intent the user intent to validate.
     */
    function validateIntent(UserIntent calldata intent) external view;

    /**
     * generate an intent Id - unique identifier for this intent.
     * the intent ID is a hash over the content of the intent (except the signature), the entrypoint and the chainid.
     */
    function getUserIntentHash(UserIntent calldata intent) external view returns (bytes32);

    /**
     * returns true if the given standard is currently executing an intent segment for the msg.sender.
     */
    function verifyExecutingIntentSegmentForStandard(IIntentStandard intentStandard) external view returns (bool);
}
