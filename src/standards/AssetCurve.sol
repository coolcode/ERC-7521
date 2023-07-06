// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {AssetType} from "../interfaces/IAssetRelease.sol";

//TODO: consider compressing all the flags into one uint256 for improved gas efficiency
//TODO: we may want to support signed numbers for the parameters

/**
 * Asset Curve struct
 * @param assetContract the address of the contract that controls the asset.
 * @param assetId the ID of the asset.
 * @param assetType the type of the asset (ETH, ERC-20, ERC-721, etc).
 * @param curveType the curve type (constant, linear, exponential).
 * @param evaluationType the evaluation type (relative, absolute).
 * @param params the parameters for the curve.
 */
struct AssetCurve {
    address assetContract;
    uint256 assetId;
    AssetType assetType;
    CurveType curveType;
    EvaluationType evaluationType;
    uint256[] params;
}

enum CurveType {
    CONSTANT,
    LINEAR,
    EXPONENTIAL,
    COUNT
}

enum EvaluationType {
    ABSOLUTE,
    RELATIVE,
    COUNT
}

/**
 * Utility functions helpful when working with AssetCurve structs.
 */
library AssetCurveLib {
    function validate(AssetCurve memory curve) public pure {
        require(curve.curveType < CurveType.COUNT, "invalid curve type");
        require(curve.assetType < AssetType.COUNT, "invalid curve asset type");
        require(curve.evaluationType < EvaluationType.COUNT, "invalid curve eval type");

        if (curve.curveType == CurveType.CONSTANT) {
            require(curve.params.length == 1, "invalid curve params");
        } else if (curve.curveType == CurveType.LINEAR) {
            require(curve.params.length == 3, "invalid curve params");
        } else if (curve.curveType == CurveType.EXPONENTIAL) {
            require(curve.params.length == 5, "invalid curve params");
        } else {
            revert("uknown curve type");
        }
    }

    function evaluate(AssetCurve memory curve, uint256 x) public pure returns (uint256 val) {
        if (curve.curveType == CurveType.CONSTANT) {
            val = curve.params[0];
        } else if (curve.curveType == CurveType.LINEAR) {
            uint256 a = curve.params[0];
            uint256 b = curve.params[1];
            uint256 max = curve.params[2];
            if (x > max) x = max;

            val = (a * x) + b;
        } else if (curve.curveType == CurveType.EXPONENTIAL) {
            uint256 a = curve.params[0];
            uint256 b = curve.params[1];
            uint256 e = curve.params[2];
            uint256 f = curve.params[3];
            uint256 max = curve.params[4];
            if (x > max) x = max;

            val = ((a * (x + f)) ** e) + b;
        } else {
            val = 0;
        }
    }

    function isRelativeEvaluation(AssetCurve memory curve) public pure returns (bool) {
        return curve.evaluationType == EvaluationType.RELATIVE;
    }

    function hash(AssetCurve memory curve) public pure returns (bytes32) {
        return keccak256(_pack(curve));
    }

    function _pack(AssetCurve memory curve) private pure returns (bytes memory ret) {
        return abi.encodePacked(curve.assetId, curve.assetType, curve.curveType, curve.evaluationType, curve.params);
    }
}
