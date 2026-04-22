// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// ============ MINIMAL INLINE DEPENDENCIES ============

abstract contract Initializable {
    uint8 private _initialized;
    bool private _initializing;

    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) ||
            (!isTopLevelCall && _initialized == 0),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) { _initializing = true; }
        _;
        if (isTopLevelCall) { _initializing = false; }
    }

    function _disableInitializers() internal {
        _initialized = type(uint8).max;
    }
}

abstract contract ContextUpgradeable is Initializable {
    function _msgSender() internal view returns (address) { return msg.sender; }
}

abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function __Ownable_init() internal initializer {
        _transferOwnership(_msgSender());
    }

    function owner() public view returns (address) { return _owner; }

    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    function _transferOwnership(address newOwner) internal {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}

abstract contract ReentrancyGuardUpgradeable is Initializable {
    uint256 private _status;

    function __ReentrancyGuard_init() internal initializer {
        _status = 1;
    }

    modifier nonReentrant() {
        require(_status != 2, "ReentrancyGuard: reentrant call");
        _status = 2;
        _;
        _status = 1;
    }
}

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

interface IERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
}

library SafeERC20 {
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transfer.selector, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "SafeERC20: transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        (bool success, bytes memory data) = address(token).call(
            abi.encodeWithSelector(token.transferFrom.selector, from, to, value)
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "SafeERC20: transferFrom failed");
    }
}

// ============ ROLES REGISTRY ============

contract RolesRegistry {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    bytes32 public constant COUNTERPARTY_ROLE = keccak256("COUNTERPARTY_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);

    function _grantRole(bytes32 role, address account) internal {
        _roles[role][account] = true;
        emit RoleGranted(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }
}

// ============ UPGRADE TIMELOCK ============

abstract contract UpgradeTimelock {
    uint256 public constant UPGRADE_DELAY = 48 hours;
    uint256 public upgradeTimelock;
    address public pendingImplementation;

    event UpgradeScheduled(address indexed implementation, uint256 releaseTime);

    function _initiateUpgrade(address newImplementation) internal {
        upgradeTimelock = block.timestamp + UPGRADE_DELAY;
        pendingImplementation = newImplementation;
        emit UpgradeScheduled(newImplementation, upgradeTimelock);
    }

    function _checkUpgradeTimelock(address newImplementation) internal view {
        require(newImplementation == pendingImplementation, "Untrusted implementation");
        require(block.timestamp >= upgradeTimelock, "Upgrade timelock not expired");
    }
}

// ============ SECURE VAULT ============

contract SecureVault is
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    RolesRegistry,
    UpgradeTimelock,
    IERC721Receiver
{
    using SafeERC20 for IERC20;

    enum State { INIT, FUNDED, LOCKED, EXECUTION_PENDING, EXECUTED, REFUNDED }

    State public currentState;
    address public counterparty;
    address public guardian;
    bytes32 public commitmentHash;
    uint256 public lockDuration;
    uint256 public lockTimestamp;
    uint256 public refundDelay;

    uint256 public constant QUARANTINE_STAKE = 0.01 ether;
    uint256 public quarantineEndTime;
    address public quarantineInitiator;

    uint256 public nonce;

    event Deposited(address indexed sender, uint256 amount);
    event StateChanged(State indexed from, State indexed to);
    event SecretRevealed(bytes32 secret);
    event Quarantined(address indexed initiator, uint256 endTime);
    event Refunded(address indexed recipient, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _owner,
        address _guardian,
        address _counterparty,
        bytes32 _commitmentHash,
        uint256 _lockDuration
    ) public initializer {
        __Ownable_init();
        __ReentrancyGuard_init();

        _transferOwnership(_owner);

        guardian = _guardian;
        counterparty = _counterparty;
        commitmentHash = _commitmentHash;
        lockDuration = _lockDuration;
        refundDelay = 24 hours;
        currentState = State.INIT;

        _grantRole(GUARDIAN_ROLE, _guardian);
        _grantRole(COUNTERPARTY_ROLE, _counterparty);
    }

    modifier inState(State _state) {
        require(currentState == _state, "Invalid state for operation");
        _;
    }

    function deposit() external payable inState(State.INIT) {
        require(msg.value > 0, "Amount must be > 0");
        currentState = State.FUNDED;
        emit Deposited(msg.sender, msg.value);
        emit StateChanged(State.INIT, State.FUNDED);
    }

    function lock() external onlyOwner inState(State.FUNDED) {
        currentState = State.LOCKED;
        lockTimestamp = block.timestamp;
        emit StateChanged(State.FUNDED, State.LOCKED);
    }

    function initiateExecution(bytes32 secret) external inState(State.LOCKED) {
        require(keccak256(abi.encodePacked(secret)) == commitmentHash, "Invalid secret");
        require(block.timestamp >= lockTimestamp + lockDuration, "Lock period not over");
        currentState = State.EXECUTION_PENDING;
        emit SecretRevealed(secret);
        emit StateChanged(State.LOCKED, State.EXECUTION_PENDING);
    }

    function execute() external nonReentrant inState(State.EXECUTION_PENDING) {
        require(msg.sender == counterparty || msg.sender == owner(), "Unauthorized");
        currentState = State.EXECUTED;
        uint256 balance = address(this).balance;
        (bool success, ) = counterparty.call{value: balance}("");
        require(success, "Transfer failed");
        emit StateChanged(State.EXECUTION_PENDING, State.EXECUTED);
    }

    function refund() external nonReentrant {
        require(msg.sender == owner(), "Only owner");
        require(
            currentState == State.FUNDED ||
            (currentState == State.LOCKED &&
                block.timestamp >= lockTimestamp + lockDuration + refundDelay),
            "Refund not available yet"
        );
        State prevState = currentState;
        uint256 balance = address(this).balance;
        currentState = State.REFUNDED;
        (bool success, ) = owner().call{value: balance}("");
        require(success, "Transfer failed");
        emit StateChanged(prevState, State.REFUNDED);
        emit Refunded(msg.sender, balance);
    }

    function initiateQuarantine() external payable {
        require(msg.value == QUARANTINE_STAKE, "Must stake 0.01 ETH");
        require(quarantineEndTime < block.timestamp, "Already quarantined");
        quarantineInitiator = msg.sender;
        quarantineEndTime = block.timestamp + 12 hours;
        emit Quarantined(msg.sender, quarantineEndTime);
    }

    function depositTokens(address token, uint256 amount) external nonReentrant {
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceAfter - balanceBefore > 0, "No tokens received");
    }

    function recoverAccount(
        address newOwner,
        uint256 deadline,
        bytes calldata ownerSignature,
        bytes calldata guardianSignature
    ) external {
        require(block.timestamp <= deadline, "Expired deadline");
        require(ownerSignature.length == 65 && guardianSignature.length == 65, "Invalid sig length");

        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(newOwner, nonce, deadline))
        ));

        address signer1 = _recover(messageHash, ownerSignature);
        address signer2 = _recover(messageHash, guardianSignature);

        require(signer1 == owner(), "Invalid owner signature");
        require(signer2 == guardian, "Invalid guardian signature");

        nonce++;
        _transferOwnership(newOwner);
    }

    function _recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }

    function assertFundIntegrity() public view {
        if (currentState == State.EXECUTED || currentState == State.REFUNDED) {
            assert(address(this).balance == 0);
        }
    }

    function scheduleUpgrade(address newImplementation) external onlyOwner {
        _initiateUpgrade(newImplementation);
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external pure override returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {
        if (msg.value == QUARANTINE_STAKE && quarantineEndTime < block.timestamp) {
            quarantineInitiator = msg.sender;
            quarantineEndTime = block.timestamp + 12 hours;
            emit Quarantined(msg.sender, quarantineEndTime);
        }
    }
}

