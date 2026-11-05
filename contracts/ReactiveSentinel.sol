// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "./interfaces/IReactive.sol";
import "./interfaces/ISubscriptionService.sol";

/**
 * @title ReactiveSentinel
 * @author Usman Bamidele (amazing200guy1-a11y)
 * @notice Autonomous Zero-Trust Cross-Chain Circuit Breaker & Liquidity Defense Engine
 *         Deployed on Reactive Network (EVM / ReactVM)
 */
contract ReactiveSentinel is IReactive {
    uint256 public constant REACTIVE_IGNORE = 0xa65f96fc9513edd4596116eab33d0b35e9d54d1c18a7ad010e46ed82916f316e;

    // Authorized Admin / Deployer
    address public owner;
    address public serviceAddress;

    // Subscribed Threat Sources: chainId => sourceContract => isMonitored
    mapping(uint256 => mapping(address => bool)) public monitoredContracts;

    // Destination Protected Vaults: chainId => targetVaultAddress
    mapping(uint256 => address) public destinationVaults;

    // Security & Threshold Metrics
    uint256 public maxSlippageBps = 500; // 5.00% max slippage allowed
    uint256 public maxVolumeThreshold = 100 ether; // 100 Native Tokens / ETH
    uint256 public totalEventsProcessed;
    uint256 public totalThreatsNeutralized;
    bool public isTripped;

    // Events
    event ThreatDetected(
        uint256 indexed originChainId,
        address indexed sourceContract,
        uint256 indexed txHash,
        uint256 anomalyScore,
        string reason
    );
    event CircuitBreakerReset(address indexed operator);
    event SubscriptionRegistered(uint256 indexed originChainId, address indexed sourceContract);
    event DestinationConfigured(uint256 indexed destChainId, address indexed vaultContract);

    modifier onlyOwner() {
        require(msg.sender == owner, "ReactiveSentinel: unauthorized");
        _;
    }

    constructor(address _serviceAddress) {
        owner = msg.sender;
        serviceAddress = _serviceAddress;
    }

    /**
     * @notice Register an origin chain event monitor with Reactive Network
     */
    function subscribeThreatFeed(
        uint256 originChainId,
        address sourceContract,
        uint256 eventTopic0
    ) external onlyOwner {
        monitoredContracts[originChainId][sourceContract] = true;

        if (serviceAddress != address(0)) {
            ISubscriptionService(serviceAddress).subscribe(
                originChainId,
                sourceContract,
                eventTopic0,
                REACTIVE_IGNORE,
                REACTIVE_IGNORE,
                REACTIVE_IGNORE
            );
        }
        emit SubscriptionRegistered(originChainId, sourceContract);
    }

    /**
     * @notice Configure destination target vault on another chain (e.g. Base, Arbitrum)
     */
    function setDestinationVault(uint256 destChainId, address vaultContract) external onlyOwner {
        require(vaultContract != address(0), "Invalid vault address");
        destinationVaults[destChainId] = vaultContract;
        emit DestinationConfigured(destChainId, vaultContract);
    }

    /**
     * @notice Adjust threat sensitivity thresholds
     */
    function setThresholds(uint256 _maxSlippageBps, uint256 _maxVolumeThreshold) external onlyOwner {
        maxSlippageBps = _maxSlippageBps;
        maxVolumeThreshold = _maxVolumeThreshold;
    }

    /**
     * @notice Autonomous React function invoked by ReactVM upon detected event
     */
    function react(LogRecord calldata log) external override {
        totalEventsProcessed++;

        // Calculate threat anomaly based on payload inspection
        (bool isMalicious, uint256 anomalyScore, string memory reason) = inspectThreat(log);

        if (isMalicious) {
            totalThreatsNeutralized++;
            isTripped = true;

            emit ThreatDetected(
                log.chain_id,
                log._contract,
                log.tx_hash,
                anomalyScore,
                reason
            );

            // Dispatch autonomous cross-chain callback to pause destination liquidity
            address destVault = destinationVaults[log.chain_id];
            if (destVault != address(0)) {
                bytes memory callbackPayload = abi.encodeWithSignature(
                    "tripCircuitBreaker(uint256,uint256,string)",
                    log.tx_hash,
                    anomalyScore,
                    reason
                );

                emit Callback(
                    log.chain_id,
                    destVault,
                    300000, // gas limit
                    callbackPayload
                );
            }
        }
    }

    /**
     * @notice Deterministic threat inspection logic
     */
    function inspectThreat(LogRecord calldata log)
        public
        view
        returns (bool isMalicious, uint256 anomalyScore, string memory reason)
    {
        // Decode volume or slippage parameter from data if present
        uint256 detectedVolume = 0;
        if (log.data.length >= 32) {
            detectedVolume = abi.decode(log.data, (uint256));
        }

        // Rule 1: High-volume flash-loan / drain anomaly
        if (detectedVolume > maxVolumeThreshold) {
            return (true, 95, "Flash-loan volume spike exceeding safety threshold");
        }

        // Rule 2: Critical topic 1 / topic 2 threat signatures (e.g. Oracle desync or emergency drain)
        if (log.topic_1 == 0xdeadbeef || log.topic_2 == 0xdeadbeef) {
            return (true, 99, "Blacklisted exploit signature detected in event topics");
        }

        // Safe
        return (false, 10, "Normal on-chain telemetry");
    }

    /**
     * @notice Reset the circuit breaker after security audit
     */
    function resetCircuitBreaker() external onlyOwner {
        isTripped = false;
        emit CircuitBreakerReset(msg.sender);
    }

    /**
     * @notice Reactive Network fee payment hook
     */
    function pay(uint256 amount) external override {
        // Handled by Reactive Payer infrastructure
    }

    // Support receiving funds for gas / operational bounties
    receive() external payable {}
}
