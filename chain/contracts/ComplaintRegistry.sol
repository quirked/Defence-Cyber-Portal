// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal registry for defence complaints: only hashes + small codes.
/// @dev Roles:
/// - intakeSigner: portal backend (register/append)
/// - analysisSigner: CERT/AI backend (recordAnalysis)
contract ComplaintRegistry {
    address public admin;
    address public intakeSigner;
    address public analysisSigner;

    event ComplaintRegistered(
        uint256 indexed complaintId,
        bytes32 indexed bundleHash,
        uint8 severityCode,
        uint256 timestamp
    );

    event EvidenceAppended(
        uint256 indexed complaintId,
        bytes32 indexed evidenceHash,
        uint256 timestamp
    );

    event AnalysisRecorded(
        uint256 indexed complaintId,
        uint16 labelCode,
        uint8 severityCode,
        bytes32 analysisHash,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }
    modifier onlyIntake() {
        require(msg.sender == intakeSigner, "not intake");
        _;
    }
    modifier onlyAnalysis() {
        require(msg.sender == analysisSigner, "not analysis");
        _;
    }

    constructor(address _intake, address _analysis) {
        admin = msg.sender;
        intakeSigner = _intake;
        analysisSigner = _analysis;
    }

    function setIntake(address a) external onlyAdmin { intakeSigner = a; }
    function setAnalysis(address a) external onlyAdmin { analysisSigner = a; }

    function registerComplaint(
        uint256 complaintId,
        bytes32 bundleHash,
        uint8 severityCode
    ) external onlyIntake {
        emit ComplaintRegistered(complaintId, bundleHash, severityCode, block.timestamp);
    }

    function appendEvidence(
        uint256 complaintId,
        bytes32 evidenceHash
    ) external onlyIntake {
        emit EvidenceAppended(complaintId, evidenceHash, block.timestamp);
    }

    function recordAnalysis(
        uint256 complaintId,
        uint16 labelCode,
        uint8 severityCode,
        bytes32 analysisHash
    ) external onlyAnalysis {
        emit AnalysisRecorded(complaintId, labelCode, severityCode, analysisHash, block.timestamp);
    }
}