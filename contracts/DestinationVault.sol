// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/**
 * @title DestinationVault
 * @author Usman Bamidele (amazing200guy1-a11y)
 * @notice Protected Liquidity Vault on destination chain (Base / Ethereum / Arbitrum)
 *         Receives autonomous circuit breaker callbacks from Reactive Network
 */
contract DestinationVault {
    address public owner;
    address public reactiveCallbackSender;
    bool public isPaused;
    uint256 public totalLockedValue;

    event VaultPaused(uint256 indexed originTxHash, uint256 anomalyScore, string reason);
    event VaultResumed(address indexed operator);
    event Deposit(address indexed user, uint256 amount);

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || msg.sender == reactiveCallbackSender,
            "DestinationVault: unauthorized caller"
        );
        _;
    }

    modifier whenNotPaused() {
        require(!isPaused, "DestinationVault: EMERGENCY_PAUSE_ACTIVE");
        _;
    }

    constructor(address _reactiveCallbackSender) {
        owner = msg.sender;
        reactiveCallbackSender = _reactiveCallbackSender;
        isPaused = false;
    }

    /**
     * @notice Callback invoked autonomously by Reactive Network when an exploit is caught
     */
    function tripCircuitBreaker(
        uint256 originTxHash,
        uint256 anomalyScore,
        string calldata reason
    ) external onlyAuthorized {
        isPaused = true;
        emit VaultPaused(originTxHash, anomalyScore, reason);
    }

    /**
     * @notice Normal user deposit
     */
    function deposit() external payable whenNotPaused {
        require(msg.value > 0, "Zero deposit");
        totalLockedValue += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Resume vault operations after manual review
     */
    function resume() external {
        require(msg.sender == owner, "Only owner");
        isPaused = false;
        emit VaultResumed(msg.sender);
    }
}
