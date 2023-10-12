// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {UserIntent} from "../../../src/interfaces/UserIntent.sol";
import {
    AssetBasedIntentCurve,
    generateFlags,
    CurveType,
    EvaluationType
} from "../../../src/standards/assetbased/AssetBasedIntentCurve.sol";
import {
    AssetBasedIntentStandard,
    AssetBasedIntentSegment
} from "../../../src/standards/assetbased/AssetBasedIntentStandard.sol";
import {AssetType} from "../../../src/standards/assetbased/utils/AssetWrapper.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";

/**
 * @title AssetBasedIntentBuilder
 * Utility functions helpful for building an asset based intent.
 */
library AssetBasedIntentBuilder {
    /**
     * Add an intent segment to the user intent.
     * @param intent The user intent to modify.
     * @param standard The standard ID for the intent segment.
     * @param segment The intent segment to add.
     * @return The updated user intent.
     */
    function addSegment(UserIntent memory intent, bytes32 standard, AssetBasedIntentSegment memory segment)
        public
        pure
        returns (UserIntent memory)
    {
        bytes32[] memory standards = new bytes32[](intent.standards.length + 1);
        for (uint256 i = 0; i < intent.standards.length; i++) {
            standards[i] = intent.standards[i];
        }
        standards[intent.standards.length] = standard;
        intent.standards = standards;

        return encodeData(intent, segment);
    }

    /**
     * Encodes the asset based intent segments onto the user intent.
     * @param intent The user intent to modify.
     * @param segment The asset based intent standard segment to encode.
     * @return The updated user intent.
     */
    function encodeData(UserIntent memory intent, AssetBasedIntentSegment memory segment)
        public
        pure
        returns (UserIntent memory)
    {
        bytes[] memory intentData = intent.intentData;
        bytes[] memory newData = new bytes[](intentData.length + 1);
        for (uint256 i = 0; i < intentData.length; i++) {
            newData[i] = intentData[i];
        }
        bytes memory raw = abi.encode(segment);
        bytes memory encoded = new bytes(raw.length - 32);
        for (uint256 j = 32; j < raw.length; j++) {
            encoded[j - 32] = raw[j];
        }
        newData[intentData.length] = encoded;
        intent.intentData = newData;

        return intent;
    }

    /**
     * Decodes the asset based intent segment at given index from the user intent.
     * @param intent The user intent to decode data from.
     * @param segmentIndex The index of segment.
     * @return The asset based intent data.
     */
    function decodeData(UserIntent memory intent, uint256 segmentIndex)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        bytes memory raw = new bytes(intent.intentData[segmentIndex].length + 32);
        assembly {
            mstore(add(raw, 32), 0x0000000000000000000000000000000000000000000000000000000000000020)
        }
        for (uint256 j = 0; j < intent.intentData[segmentIndex].length; j++) {
            raw[j + 32] = intent.intentData[segmentIndex][j];
        }
        AssetBasedIntentSegment memory decoded = abi.decode(raw, (AssetBasedIntentSegment));
        return decoded;
    }
}

/**
 * @title AssetBasedIntentSegmentBuilder
 * Utility functions helpful for building an asset based intent segment.
 */
library AssetBasedIntentSegmentBuilder {
    /**
     * Create a new intent segment with the specified parameters.
     * @param callData The data for an intended call.
     * @return intent The created user intent segment.
     */
    function create(bytes memory callData) public pure returns (AssetBasedIntentSegment memory) {
        AssetBasedIntentCurve[] memory assetReleases;
        AssetBasedIntentCurve[] memory assetRequirements;

        return AssetBasedIntentSegment({
            callData: callData,
            assetReleases: assetReleases,
            assetRequirements: assetRequirements
        });
    }

    /**
     * Internal helper function to determine the type of the curve based on its parameters.
     */
    function getCurveType(int256[] memory params) internal pure returns (CurveType) {
        if (params.length == 4) return CurveType.EXPONENTIAL;
        if (params.length == 3) return CurveType.LINEAR;
        return CurveType.CONSTANT;
    }

    /**
     * Private helper function to add an asset release curve to a user intent.
     * Add an asset release for ETH to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param curve The curve parameters for the asset release.
     * @return The updated user intent segment.
     */
    function releaseETH(AssetBasedIntentSegment memory segment, int256[] memory curve)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetRelCurve(segment, address(0), uint256(0), AssetType.ETH, curve);
    }

    /**
     * Add an asset release for ERC20 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC20 token contract.
     * @param curve The curve parameters for the asset release.
     * @return The updated user intent segment.
     */
    function releaseERC20(AssetBasedIntentSegment memory segment, address addr, int256[] memory curve)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetRelCurve(segment, addr, uint256(0), AssetType.ERC20, curve);
    }

    /**
     * Add an asset release for ERC721 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC721 token contract.
     * @param id The ID of the ERC721 token.
     * @param curve The curve parameters for the asset release.
     * @return The updated user intent segment.
     */
    function releaseERC721(AssetBasedIntentSegment memory segment, address addr, uint256 id, int256[] memory curve)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetRelCurve(segment, addr, id, AssetType.ERC721, curve);
    }

    /**
     * Add an asset release for ERC1155 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC1155 token contract.
     * @param id The ID of the ERC1155 token.
     * @param curve The curve parameters for the asset release.
     * @return The updated user intent segment.
     */
    function releaseERC1155(AssetBasedIntentSegment memory segment, address addr, uint256 id, int256[] memory curve)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetRelCurve(segment, addr, id, AssetType.ERC1155, curve);
    }

    /**
     * Add an end state required asset of ETH to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param curve The curve parameters for the asset requirement.
     * @param relative Boolean flag to indicate if the curve is relative.
     * @return The updated user intent segment.
     */
    function requireETH(AssetBasedIntentSegment memory segment, int256[] memory curve, bool relative)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetReqCurve(segment, address(0), uint256(0), AssetType.ETH, curve, relative);
    }

    /**
     * Add an end state required asset of ERC20 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC20 token contract.
     * @param curve The curve parameters for the asset requirement.
     * @param relative Boolean flag to indicate if the curve is relative.
     * @return The updated user intent segment.
     */
    function requireERC20(AssetBasedIntentSegment memory segment, address addr, int256[] memory curve, bool relative)
        public
        pure
        returns (AssetBasedIntentSegment memory)
    {
        return _addAssetReqCurve(segment, addr, uint256(0), AssetType.ERC20, curve, relative);
    }

    /**
     * Add an end state required asset of ERC721 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC721 token contract.
     * @param id The ID of the ERC721 token.
     * @param curve The curve parameters for the asset requirement.
     * @param relative Boolean flag to indicate if the curve is relative.
     * @return The updated user intent segment.
     */
    function requireERC721(
        AssetBasedIntentSegment memory segment,
        address addr,
        uint256 id,
        int256[] memory curve,
        bool relative
    ) public pure returns (AssetBasedIntentSegment memory) {
        return _addAssetReqCurve(segment, addr, id, AssetType.ERC721, curve, relative);
    }

    /**
     * Add an end state required asset of ERC1155 tokens to the user intent segment.
     * @param segment The user intent segment to modify.
     * @param addr The address of the ERC1155 token contract.
     * @param id The ID of the ERC1155 token.
     * @param curve The curve parameters for the asset requirement.
     * @param relative Boolean flag to indicate if the curve is relative.
     * @return The updated user intent segment.
     */
    function requireERC1155(
        AssetBasedIntentSegment memory segment,
        address addr,
        uint256 id,
        int256[] memory curve,
        bool relative
    ) public pure returns (AssetBasedIntentSegment memory) {
        return _addAssetReqCurve(segment, addr, id, AssetType.ERC1155, curve, relative);
    }

    /**
     * Private helper function to add an asset release curve to a user intent segment.
     */
    function _addAssetReqCurve(
        AssetBasedIntentSegment memory segment,
        address assetContract,
        uint256 assetId,
        AssetType assetType,
        int256[] memory curveParams,
        bool isRelative
    ) private pure returns (AssetBasedIntentSegment memory) {
        //create new curve element
        EvaluationType evalType = EvaluationType.ABSOLUTE;
        if (isRelative) evalType = EvaluationType.RELATIVE;
        AssetBasedIntentCurve memory curve = AssetBasedIntentCurve({
            assetContract: assetContract,
            assetId: assetId,
            flags: generateFlags(assetType, getCurveType(curveParams), evalType),
            params: curveParams
        });

        //clone previous array and add new element
        AssetBasedIntentCurve[] memory assetRequirements = new AssetBasedIntentCurve[](
                segment.assetRequirements.length + 1
            );
        for (uint256 i = 0; i < segment.assetRequirements.length; i++) {
            assetRequirements[i] = segment.assetRequirements[i];
        }
        assetRequirements[segment.assetRequirements.length] = curve;
        segment.assetRequirements = assetRequirements;

        return segment;
    }

    /**
     * Private helper function to add an asset release curve to a user intent segment.
     */
    function _addAssetRelCurve(
        AssetBasedIntentSegment memory segment,
        address assetContract,
        uint256 assetId,
        AssetType assetType,
        int256[] memory curveParams
    ) private pure returns (AssetBasedIntentSegment memory) {
        //create new curve element
        AssetBasedIntentCurve memory curve = AssetBasedIntentCurve({
            assetContract: assetContract,
            assetId: assetId,
            flags: generateFlags(assetType, getCurveType(curveParams), EvaluationType.ABSOLUTE),
            params: curveParams
        });

        //clone previous array and add new element
        AssetBasedIntentCurve[] memory assetReleases = new AssetBasedIntentCurve[](
                segment.assetReleases.length + 1
            );
        for (uint256 i = 0; i < segment.assetReleases.length; i++) {
            assetReleases[i] = segment.assetReleases[i];
        }
        assetReleases[segment.assetReleases.length] = curve;
        segment.assetReleases = assetReleases;

        return segment;
    }
}

/**
 * @title AssetBasedIntentCurveBuilder
 * Utility functions helpful for building an asset based intent curve.
 */
library AssetBasedIntentCurveBuilder {
    /**
     * @dev Helper function to generate curve parameters for a constant curve.
     * @param amount The constant value for the curve.
     * @return params The array containing the curve parameters.
     */
    function constantCurve(int256 amount) public pure returns (int256[] memory) {
        int256[] memory params = new int256[](1);
        params[0] = amount;
        return params;
    }

    /**
     * @dev Helper function to generate curve parameters for a linear curve.
     * @param m The slope of the linear curve.
     * @param b The y-intercept of the linear curve.
     * @param max The maximum x value for the curve.
     * @param flipY Boolean flag to indicate if the curve should be evaluated from right to left.
     * @return params The array containing the curve parameters.
     */
    function linearCurve(int256 m, int256 b, uint256 max, bool flipY) public pure returns (int256[] memory) {
        int256[] memory params = new int256[](3);
        int256 signedMax = int256(max);
        if (flipY) signedMax = -signedMax;
        params[0] = m;
        params[1] = b;
        params[2] = signedMax;
        return params;
    }

    /**
     * @dev Helper function to generate curve parameters for an exponential curve.
     * @param m The multiplier for the exponential curve.
     * @param b The base for the exponential curve.
     * @param e The exponent for the exponential curve.
     * @param max The maximum x value for the curve.
     * @param flipY Boolean flag to indicate if the curve should be evaluated from right to left.
     * @return params The array containing the curve parameters.
     */
    function exponentialCurve(int256 m, int256 b, int256 e, uint256 max, bool flipY)
        public
        pure
        returns (int256[] memory)
    {
        int256[] memory params = new int256[](4);
        int256 signedMax = int256(max);
        if (flipY) signedMax = -signedMax;
        params[0] = m;
        params[1] = b;
        params[2] = e;
        params[3] = signedMax;
        return params;
    }
}
