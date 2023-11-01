// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/* solhint-disable private-vars-leading-underscore */

import "forge-std/Test.sol";
import {EthCurve, isRelativeEvaluation, validate, evaluate} from "../utils/curves/EthCurve.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {IIntentDelegate} from "../interfaces/IIntentDelegate.sol";
import {IIntentStandard} from "../interfaces/IIntentStandard.sol";
import {UserIntent} from "../interfaces/UserIntent.sol";
import {IntentSolution, IntentSolutionLib} from "../interfaces/IntentSolution.sol";
import {Exec, RevertReason} from "../utils/Exec.sol";
import {_balanceOf} from "../utils/wrappers/EthWrapper.sol";
import {Strings} from "openzeppelin/utils/Strings.sol";

/**
 * Eth Require Intent Segment struct
 * @param standard intent standard id for segment.
 * @param requirement asset that is required to be owned by the account at the end of the solution execution.
 */
struct EthRequireIntentSegment {
    bytes32 standard;
    EthCurve requirement;
}

contract EthRequireIntentStandard is IIntentStandard {
    using IntentSolutionLib for IntentSolution;
    using RevertReason for bytes;

    /**
     * Validate intent segment structure (typically just formatting).
     * @param segmentData the intent segment that is about to be solved.
     */
    function validateIntentSegment(bytes calldata segmentData) external pure {
        if (segmentData.length > 0) {
            EthRequireIntentSegment calldata segment = parseIntentSegment(segmentData);
            validate(segment.requirement);
        }
    }

    /**
     * Performs part or all of the execution for an intent.
     * @param solution the full solution being executed.
     * @param executionIndex the current index of execution (used to get the UserIntent to execute for).
     * @param segmentIndex the current segment to execute for the intent.
     * @param context context data from the previous step in execution (no data means execution is just starting).
     * @return context to remember for further execution.
     */
    function executeIntentSegment(
        IntentSolution calldata solution,
        uint256 executionIndex,
        uint256 segmentIndex,
        bytes memory context
    ) external view returns (bytes memory) {
        UserIntent calldata intent = solution.intents[solution.getIntentIndex(executionIndex)];
        if (intent.intentData[segmentIndex].length > 0) {
            uint256 evaluateAt = 0;
            if (solution.timestamp > intent.timestamp) {
                evaluateAt = solution.timestamp - intent.timestamp;
            }
            EthRequireIntentSegment calldata segment = parseIntentSegment(intent.intentData[segmentIndex]);

            // check requirement
            _checkRequirement(segment, evaluateAt, intent.sender);

            if (segmentIndex + 1 < intent.intentData.length && intent.intentData[segmentIndex + 1].length > 0) {
                return context;
            }
        }
        return "";
    }

    function parseIntentSegment(bytes calldata segmentData)
        internal
        pure
        returns (EthRequireIntentSegment calldata segment)
    {
        assembly {
            segment := segmentData.offset
        }
    }

    function _checkRequirement(EthRequireIntentSegment calldata intentSegment, uint256 evaluateAt, address owner)
        private
        view
    {
        int256 requiredBalance = evaluate(intentSegment.requirement, evaluateAt);
        uint256 currentBalance = _balanceOf(owner);
        require(
            currentBalance >= uint256(requiredBalance),
            string.concat(
                "insufficient balance (required: ",
                Strings.toString(requiredBalance),
                ", current: ",
                Strings.toString(currentBalance),
                ")"
            )
        );
    }

    function testNothing() public {}
}
