// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import {IIntentStandard} from "../interfaces/IIntentStandard.sol";
import {IIntentDelegate} from "../interfaces/IIntentDelegate.sol";
import {UserIntent} from "../interfaces/UserIntent.sol";
import {IntentSolution, IntentSolutionLib} from "../interfaces/IntentSolution.sol";
import {Strings} from "openzeppelin/utils/Strings.sol";
import {EthReleaseDelegate} from "./delegates/EthReleaseDelegate.sol";
import {popFromCalldata} from "./utils/ContextData.sol";
import {getSegmentWord} from "./utils/SegmentData.sol";
import {evaluateConstantCurve, encodeConstantCurve, encodeAsUint96} from "./utils/CurveCoder.sol";

/**
 * Eth Release Intent Standard
 * @dev data
 *   [bytes32] standard - the intent standard identifier
 *   [uint96]  amount - amount required
 *   [uint8]   amountMult - amount multiplier (final_amount = amount << amountMult)
 *   [bytes1]  flags - negative [nxxx xxxx]
 */
contract EthRelease is IIntentStandard, EthReleaseDelegate {
    using IntentSolutionLib for IntentSolution;

    /**
     * Validate intent segment structure (typically just formatting).
     * @param segmentData the intent segment that is about to be solved.
     */
    function validateIntentSegment(bytes calldata segmentData) external pure {
        require(segmentData.length != 46, "ETH Release data length invalid");
    }

    /**
     * Performs part or all of the execution for an intent.
     * @param solution the full solution being executed.
     * @param executionIndex the current index of execution (used to get the UserIntent to execute for).
     * @param segmentIndex the current segment to execute for the intent.
     * @param context context data from the previous step in execution (no data means execution is just starting).
     * @return newContext to remember for further execution.
     */
    function executeIntentSegment(
        IntentSolution calldata solution,
        uint256 executionIndex,
        uint256 segmentIndex,
        bytes calldata context
    ) external returns (bytes memory) {
        UserIntent calldata intent = solution.intents[solution.getIntentIndex(executionIndex)];

        //evaluate data
        bytes32 data = getSegmentWord(intent.intentData[segmentIndex], 32);
        int256 releaseAmount = evaluateConstantCurve(data);

        //release
        address nextExecutingIntentSender = solution.intents[solution.getIntentIndex(executionIndex + 1)].sender;
        if (releaseAmount > 0) {
            bytes memory releaseEthDelegate = _encodeReleaseEth(nextExecutingIntentSender, uint256(releaseAmount));
            IIntentDelegate(address(intent.sender)).generalizedIntentDelegateCall(releaseEthDelegate);
        }

        //return context unchanged
        return context;
    }

    /**
     * Helper function to encode intent standard segment data.
     * @param standardId the entry point identifier for this standard
     * @param amount amount required
     * @return the fully encoded intent standard segment data
     */
    function encodeData(bytes32 standardId, int256 amount) external pure returns (bytes memory) {
        (uint96 adjustedAmount, uint8 amountMult, bool amountNegative) = encodeAsUint96(amount);
        bytes32 data = encodeConstantCurve(uint96(adjustedAmount), amountMult, amountNegative, false);
        return abi.encodePacked(standardId, bytes14(data));
    }
}