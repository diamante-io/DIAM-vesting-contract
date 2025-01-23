// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import {console} from "../lib/forge-std/src/console.sol";


/**
 * @title DIAMVesting
 * @dev A vesting contract for DIAM token distribution with multiple vesting schedules
 */
contract DIAMVesting is ReentrancyGuard, Pausable, Ownable(msg.sender) {
    using SafeERC20 for IERC20;
    using Math for uint256;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    enum VestingType {
        SimpleCliff,
        LinearCliff
    }

        event PartialRevocation(
        uint256 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount
    );

    struct VestingSchedule {
        uint256 scheduleId;
        address beneficiary;
        uint256 totalAmount;
        uint256 cliffPeriod; // in months
        uint256 vestingPeriod; // in months
        VestingType vestingType;
        uint256 releasePercentage;
        uint256 startTime;
        uint256 releasedAmount;
        bool isActive;
        uint256 lastProcessedDay; 
    }

    struct BatchVestingParams {
        address beneficiary;
        uint256 totalAmount;
        uint256 cliffPeriod;
        uint256 vestingPeriod;
        VestingType vestingType;
        uint256 releasePercentage;
    }

    IERC20 public diamToken;

    uint256 private nextScheduleId = 1;

    mapping(uint256 => VestingSchedule) public vestingSchedules;
    mapping(address => uint256[]) public beneficiarySchedules;

    event VestingScheduleCreated(
        uint256 indexed scheduleId,
        address indexed beneficiary,
        uint256 totalAmount,
        uint256 cliffPeriod,
        uint256 vestingPeriod,
        VestingType vestingType,
        uint256 releasePercentage
    );
    event TokensReleased(
        uint256 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount
    );
    event VestingScheduleRevoked(
        uint256 indexed scheduleId,
        address indexed beneficiary,
        uint256 amount
    );

    constructor(address _tokenAddress) {
        require(_tokenAddress != address(0), "Token address cannot be zero");
        diamToken = IERC20(_tokenAddress);

        // _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /**
     * @dev Creates multiple vesting schedules in a single transaction
     */
    function createBatchVestingSchedules(
        BatchVestingParams[] calldata _params
    ) external nonReentrant onlyOwner {
        uint256 totalAmount = calculateTotalAmount(_params);
        diamToken.safeTransferFrom(msg.sender, address(this), totalAmount);

        for (uint256 i = 0; i < _params.length; i++) {
            _createVestingSchedule(_params[i]);
        }
    }



    /**
     * @dev Internal function to calculate total amount for batch vesting
     */
    function calculateTotalAmount(BatchVestingParams[] calldata _params)
        internal
        pure
        returns (uint256 totalAmount)
    {
        for (uint256 i = 0; i < _params.length; i++) {
            totalAmount += _params[i].totalAmount;
        }
    }

    /**
     * @dev Internal function to create a vesting schedule
     */
    function _createVestingSchedule(BatchVestingParams calldata params)
        internal
    {
        uint256 scheduleId = nextScheduleId++;
        console.log(params.beneficiary, " < 0-0-0-");
        vestingSchedules[scheduleId] = VestingSchedule({
            scheduleId: scheduleId,
            beneficiary: params.beneficiary,
            totalAmount: params.totalAmount,
            cliffPeriod: params.cliffPeriod,
            vestingPeriod: params.vestingPeriod,
            vestingType: params.vestingType,
            releasePercentage: params.releasePercentage,
            startTime: block.timestamp,
            releasedAmount: 0,
            isActive: true,
            lastProcessedDay: 0
        });

        beneficiarySchedules[params.beneficiary].push(scheduleId);

        emit VestingScheduleCreated(
            scheduleId,
            params.beneficiary,
            params.totalAmount,
            params.cliffPeriod,
            params.vestingPeriod,
            params.vestingType,
            params.releasePercentage
        );
    }

    /**
     * @dev Processes token releases for multiple schedules
     */
    function processTokenReleases(uint256[] calldata _scheduleIds)
        external
        nonReentrant
        whenNotPaused
    //   onlyOwner
   
    {
        for (uint256 i = 0; i < _scheduleIds.length; i++) {
            console.log(_scheduleIds[i], " processing ID");
            _processScheduleRelease(_scheduleIds[i]);
        }
    }

    /**
     * @dev Internal function to process token release for a schedule
     */
    function _processScheduleRelease(uint256 _scheduleId) internal  {
        VestingSchedule storage schedule = vestingSchedules[_scheduleId];

        console.log(msg.sender, schedule.beneficiary);

        require(msg.sender == schedule.beneficiary, "Unauteehorized");

        require(schedule.isActive, "Schedule not active");
        console.log(msg.sender);

        uint256 releasableAmount = calculateReleasableAmount(schedule);
        if (releasableAmount > 0) {
            schedule.releasedAmount += releasableAmount;
            schedule.lastProcessedDay = block.timestamp / 1 days;

            diamToken.safeTransfer(schedule.beneficiary, releasableAmount);

            emit TokensReleased(
                schedule.scheduleId,
                schedule.beneficiary,
                releasableAmount
            );
        }
    }

    /**
     * @dev Calculates releasable amount for a schedule
     */
    function calculateReleasableAmount(VestingSchedule storage schedule)
        internal
        view
        returns (uint256)
    {
        // Check for cliff period
        uint256 cliffEndTime = schedule.startTime +
            (schedule.cliffPeriod * 30 days);
        if (block.timestamp < cliffEndTime) return 0;

        // Calculate vesting duration
        uint256 vestingDuration = schedule.vestingPeriod * 30 days;
        uint256 elapsedTime = block.timestamp - schedule.startTime;

        if (elapsedTime >= vestingDuration) {
            return schedule.totalAmount - schedule.releasedAmount;
        }

        return
            ((schedule.totalAmount * elapsedTime) / vestingDuration) -
            schedule.releasedAmount;
    }

        /**
     * @dev Returns all schedule IDs for a beneficiary
     */
    function getBeneficiarySchedules(
        address _beneficiary
    ) external view returns (uint256[] memory) {
        return beneficiarySchedules[_beneficiary];
    }

        /**
     * @dev Partially revokes a vesting schedule
     */
    function partialRevoke(
        uint256 _scheduleId,
        uint256 _amount
    ) external onlyOwner {
        VestingSchedule storage schedule = vestingSchedules[_scheduleId];
        require(schedule.isActive, "Schedule not active");

        // Check that the amount being revoked is valid
        (bool successSub, uint256 remainingAmount) = Math.trySub(
            schedule.totalAmount,
            schedule.releasedAmount
        );
        if (!successSub) {
            revert("Subtraction overflow in remaining amount check");
        }

        require(_amount <= remainingAmount, "Invalid revocation amount");

        // Update the totalAmount after revocation
        (bool successSubFinal, uint256 newTotalAmount) = Math.trySub(
            schedule.totalAmount,
            _amount
        );
        if (!successSubFinal) {
            revert("Subtraction overflow in totalAmount update");
        }
        schedule.totalAmount = newTotalAmount;

        // Transfer the revoked amount to the caller (admin)
        diamToken.safeTransfer(msg.sender, _amount);

        // Emit event for partial revocation
        emit PartialRevocation(_scheduleId, schedule.beneficiary, _amount);
    }

    /**
     * @dev Fully revokes a vesting schedule
     */
    function revokeSchedule(uint256 _scheduleId) external onlyOwner {
        VestingSchedule storage schedule = vestingSchedules[_scheduleId];
        require(schedule.isActive, "Schedule not active");

        // Calculate the remaining tokens
        (bool successSub, uint256 remainingTokens) = Math.trySub(
            schedule.totalAmount,
            schedule.releasedAmount
        );
        if (!successSub) {
            revert("Subtraction overflow in remaining tokens calculation");
        }

        // Mark the schedule as inactive
        schedule.isActive = false;

        // If there are remaining tokens, transfer them to the admin (msg.sender)
        if (remainingTokens > 0) {
            diamToken.safeTransfer(msg.sender, remainingTokens);
        }

        // Emit event for vesting schedule revocation
        emit VestingScheduleRevoked(
            _scheduleId,
            schedule.beneficiary,
            remainingTokens
        );
    }

}
