// // SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "../lib/forge-std/src/Test.sol";
import "../src/DIAMVesting.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {console} from "../lib/forge-std/src/console.sol";

// Mock ERC20 Token for testing purposes
contract MockERC20 is ERC20 {
    address public admin = address(1);

    constructor() ERC20("DIAM", "DIAM") {
        _mint(admin, 1_000_000 ether); // Mint 1,000,000 tokens to admin for testing
    }
}

contract DIAMVestingTest is Test {
    DIAMVesting public vesting;
    MockERC20 public token;
    address public _InitAdmin = address(1);
    address public admin = address(2);
    address public beneficiary = address(3);

    function setUp() public {
        vm.prank(_InitAdmin); // Set admin as deployer

        token = new MockERC20();

        vm.prank(_InitAdmin); // Set admin as deployer

        // Deploy DIAMVesting contract
        vesting = new DIAMVesting(address(token));
        console.log(vesting.owner(), " ICP PPPPPPPPPP");

        vm.prank(address(0));
        token.transfer(_InitAdmin, token.balanceOf(address(0)));

        vm.prank(_InitAdmin);
        token.approve(address(vesting), type(uint256).max);

        console.log("Admin Balance:", token.balanceOf(_InitAdmin));

        console.log("Admin Balance:", token.balanceOf(admin));
        console.log("Beneficiary Balance:", token.balanceOf(beneficiary));
        console.log(
            "Allowance (Beneficiary -> Vesting):",
            token.allowance(beneficiary, address(vesting))
        );
    }

    /**
     * @dev Test creating batch vesting schedules
     */
    function testCreateBatchVestingSchedules() public {
        DIAMVesting.BatchVestingParams[]
            memory params = new DIAMVesting.BatchVestingParams[](2);

        params[0] = DIAMVesting.BatchVestingParams({
            beneficiary: beneficiary,
            totalAmount: 100 ether,
            cliffPeriod: 3,
            vestingPeriod: 12,
            vestingType: DIAMVesting.VestingType.SimpleCliff,
            releasePercentage: 10
        });
        params[1] = DIAMVesting.BatchVestingParams({
            beneficiary: address(4),
            totalAmount: 200 ether,
            cliffPeriod: 6,
            vestingPeriod: 24,
            vestingType: DIAMVesting.VestingType.LinearCliff,
            releasePercentage: 20
        });

        // Log token balances for debugging
        console.log("Admin balance before:", token.balanceOf(_InitAdmin));

        // Create batch vesting schedules
        vm.prank(_InitAdmin);
        vesting.createBatchVestingSchedules(params);

        // Verify the schedules for the first beneficiary
        uint256[] memory schedules = vesting.getBeneficiarySchedules(
            beneficiary
        );
        assertEq(schedules.length, 1);

        // DIAMVesting.VestingSchedule memory schedule = vesting.getVestingSchedule(schedules[0]);
        (
            uint256 _scheduleId,
            address _beneficiary,
            uint256 totalAmount,
            uint256 cliffPeriod,
            uint256 vestingPeriod,
            DIAMVesting.VestingType vestingType,
            uint256 releasePercentage,
            uint256 startTime,
            uint256 releasedAmount,
            bool isActive,
            uint256 lastProcessedDay
        ) = vesting.vestingSchedules(schedules[0]);

        DIAMVesting.VestingSchedule memory schedule = DIAMVesting
            .VestingSchedule({
                scheduleId: _scheduleId,
                beneficiary: _beneficiary,
                totalAmount: totalAmount,
                cliffPeriod: cliffPeriod,
                vestingPeriod: vestingPeriod,
                vestingType: vestingType,
                releasePercentage: releasePercentage,
                startTime: startTime,
                releasedAmount: releasedAmount,
                isActive: isActive,
                lastProcessedDay: lastProcessedDay
            });
        assertEq(schedule.totalAmount, 100 ether);
        assertEq(schedule.cliffPeriod, 3);
        assertEq(schedule.vestingPeriod, 12);
        assertEq(schedule.releasePercentage, 10);
        assertEq(schedule.beneficiary, beneficiary);
    }

    /**
     * @dev Test processing token releases after the cliff period
     */
    function testProcessTokenReleases() public {
        // Define batch vesting parameters
        DIAMVesting.BatchVestingParams[]
            memory params = new DIAMVesting.BatchVestingParams[](2);
        params[0] = DIAMVesting.BatchVestingParams({
            beneficiary: beneficiary,
            totalAmount: 10 ether, // Total amount of tokens for vesting
            cliffPeriod: 1, // 1-month cliff
            vestingPeriod: 12, // 12 months total vesting period
            vestingType: DIAMVesting.VestingType.SimpleCliff,
            releasePercentage: 10 // 10% released at each interval
        });

        // Log initial admin balance for debugging
        console.log(
            token.balanceOf(_InitAdmin),
            "Admin balance before vesting"
        );

        // Create batch vesting schedules
        vm.prank(_InitAdmin); // Set the sender as admin
        vesting.createBatchVestingSchedules(params);

        // Retrieve the schedule for the beneficiary
        uint256[] memory schedules = vesting.getBeneficiarySchedules(
            beneficiary
        );
        uint256 scheduleId = schedules[0];
        console.log("Schedule ID:", scheduleId);

        // Fast forward time past the cliff period (1 month)
        vm.warp(block.timestamp + 31 days); // Move the block timestamp forward by 31 days

        // Process token releases
        vm.prank(beneficiary); // Set the sender as admin for processing releases
        vesting.processTokenReleases(schedules);

        // Fetch the updated schedule details
        (
            uint256 _scheduleId,
            address _beneficiary,
            uint256 totalAmount,
            uint256 cliffPeriod,
            uint256 vestingPeriod,
            DIAMVesting.VestingType vestingType,
            uint256 releasePercentage,
            uint256 startTime,
            uint256 releasedAmount,
            bool isActive,
            uint256 lastProcessedDay
        ) = vesting.vestingSchedules(scheduleId);

        DIAMVesting.VestingSchedule memory schedule = DIAMVesting
            .VestingSchedule({
                scheduleId: _scheduleId,
                beneficiary: _beneficiary,
                totalAmount: totalAmount,
                cliffPeriod: cliffPeriod,
                vestingPeriod: vestingPeriod,
                vestingType: vestingType,
                releasePercentage: releasePercentage,
                startTime: startTime,
                releasedAmount: releasedAmount,
                isActive: isActive,
                lastProcessedDay: lastProcessedDay
            });
        // Log the released amount for debugging
        console.log("Released Amount:", schedule.releasedAmount);

        // Assertions to validate expected behavior
        assertGt(schedule.releasedAmount, 0); // Ensure some tokens are released
        assertEq(
            token.balanceOf(beneficiary),
            schedule.releasedAmount,
            "Released amount should match beneficiary's token balance"
        );

        // Log the beneficiary's balance
        console.log("Beneficiary balance:", token.balanceOf(beneficiary));
    }

    /**
     * @dev Test partial revocation of a vesting schedule
     */
    function testPartialRevoke() public {
        DIAMVesting.BatchVestingParams[]
            memory params = new DIAMVesting.BatchVestingParams[](1);
        params[0] = DIAMVesting.BatchVestingParams({
            beneficiary: beneficiary,
            totalAmount: 100 ether,
            cliffPeriod: 1,
            vestingPeriod: 12,
            vestingType: DIAMVesting.VestingType.SimpleCliff,
            releasePercentage: 10
        });

        // Create batch vesting schedules
        vm.prank(_InitAdmin);
        vesting.createBatchVestingSchedules(params);

        uint256[] memory schedules = vesting.getBeneficiarySchedules(
            beneficiary
        );
        uint256 scheduleId = schedules[0];

        // Partially revoke the schedule (reduce total amount by 50 ether)
        vm.prank(_InitAdmin);
        vesting.partialRevoke(scheduleId, 50 ether);

        // Verify the updated schedule
        // DIAMVesting.VestingSchedule memory schedule = vesting.getVestingSchedule(scheduleId);
        (
            uint256 _scheduleId,
            address _beneficiary,
            uint256 totalAmount,
            uint256 cliffPeriod,
            uint256 vestingPeriod,
            DIAMVesting.VestingType vestingType,
            uint256 releasePercentage,
            uint256 startTime,
            uint256 releasedAmount,
            bool isActive,
            uint256 lastProcessedDay
        ) = vesting.vestingSchedules(scheduleId);

        DIAMVesting.VestingSchedule memory schedule = DIAMVesting
            .VestingSchedule({
                scheduleId: _scheduleId,
                beneficiary: _beneficiary,
                totalAmount: totalAmount,
                cliffPeriod: cliffPeriod,
                vestingPeriod: vestingPeriod,
                vestingType: vestingType,
                releasePercentage: releasePercentage,
                startTime: startTime,
                releasedAmount: releasedAmount,
                isActive: isActive,
                lastProcessedDay: lastProcessedDay
            });
        assertEq(schedule.totalAmount, 50 ether);
    }

    /**
     * @dev Test full revocation of a vesting schedule
     */
    function testFullRevoke() public {
        DIAMVesting.BatchVestingParams[]
            memory params = new DIAMVesting.BatchVestingParams[](1);
        params[0] = DIAMVesting.BatchVestingParams({
            beneficiary: beneficiary,
            totalAmount: 100 ether,
            cliffPeriod: 1,
            vestingPeriod: 12,
            vestingType: DIAMVesting.VestingType.SimpleCliff,
            releasePercentage: 10
        });

        // Create batch vesting schedules
        vm.prank(_InitAdmin);
        vesting.createBatchVestingSchedules(params);

        uint256[] memory schedules = vesting.getBeneficiarySchedules(
            beneficiary
        );
        uint256 scheduleId = schedules[0];

        // Fully revoke the schedule
        vm.prank(_InitAdmin);
        vesting.revokeSchedule(scheduleId);

        // Verify the schedule is inactive
        (
            uint256 _scheduleId,
            address _beneficiary,
            uint256 totalAmount,
            uint256 cliffPeriod,
            uint256 vestingPeriod,
            DIAMVesting.VestingType vestingType,
            uint256 releasePercentage,
            uint256 startTime,
            uint256 releasedAmount,
            bool isActive,
            uint256 lastProcessedDay
        ) = vesting.vestingSchedules(scheduleId);

        DIAMVesting.VestingSchedule memory schedule = DIAMVesting
            .VestingSchedule({
                scheduleId: _scheduleId,
                beneficiary: _beneficiary,
                totalAmount: totalAmount,
                cliffPeriod: cliffPeriod,
                vestingPeriod: vestingPeriod,
                vestingType: vestingType,
                releasePercentage: releasePercentage,
                startTime: startTime,
                releasedAmount: releasedAmount,
                isActive: isActive,
                lastProcessedDay: lastProcessedDay
            });
        assertFalse(schedule.isActive);
    }
}
