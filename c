// SPDX-License-Identifier: MIT
pragma solidity 0.8.22;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "./PlanetsMetadataInterface.sol";
import {DynamicTraits} from "./DynamicTraits.sol";

contract DrGreenNFT is ERC721, ERC2981, Ownable, ERC721Pausable, DynamicTraits {
    PlanetsMetadataInterface _planetsMetadata;

    event NFTMinted(
        string mintType,
        address to,
        uint256 tokenId,
        uint256 metadataId,
        uint256 price
    );
    event NFTTransferred(address from, address to, uint256 tokenId);
    event FundsTransferred(address, uint256);
    event UpdateTokenURI(uint16 tokenId, string uri, uint256 time);

    using Strings for uint256;

    struct NftMinted {
        uint8 goldMinted;
        uint8 platinumMinted;
        uint8 standardMinted;
    }

    // address of the owner who whitelists the user
    address private whitelistingOwner;

    // total supply of NFTs
    uint16 private constant MAX_SUPPLY = 5145;
    uint16 private constant NFTS_PER_PLANET = 251;
    uint256 public PRICE_PER_MINT = 0.0002 ether;
    bytes32 private clientCountKey =
        0x636c69656e74436f756e74000000000000000000000000000000000000000000;
    bytes32 private txCountKey =
        0x7478436f756e7400000000000000000000000000000000000000000000000000;
    bytes32 private txVolumeKey =
        0x7478566f6c756d65000000000000000000000000000000000000000000000000;

    // address to validate signature for update token URI
    address public _platformAddress;
    string public _baseTokenURI;
    mapping(uint256 => string) private _tokenURIs;
    mapping(address => NftMinted) public nftMintedCounts;

    uint16 private STANDARD_CURR_INDEX = 126;

    // define total NFTs count in Platinum
    uint8 public constant PLATINUM_MAX_SUPPLY = 50;
    uint8 private PLATINUM_START_INDEX = 76;
    uint8 public TOTAL_PLATINUM_MINTED = 0;

    // define total NFTs count in Gold
    uint8 public constant GOLD_MAX_SUPPLY = 75;
    uint8 private GOLD_START_INDEX = 1;
    uint8 public TOTAL_GOLD_MINTED = 0;

    //TODO confirm name and short Name
    constructor(
        address _owner,
        address planetsMetadataAddr,
        string memory baseTokenURI,
        address _whitelistingOwner,
        string memory traitMetadataUri,
        address platformAddress
    ) ERC721("Dr Green NFT", "DRG") Ownable(_owner) {
        _planetsMetadata = PlanetsMetadataInterface(planetsMetadataAddr);
        _baseTokenURI = baseTokenURI;
        whitelistingOwner = _whitelistingOwner;
        _setTraitMetadataURI(traitMetadataUri);
        _platformAddress = platformAddress;
        _setDefaultRoyalty(_owner, 900);
    }

    // This is the modifier for the whitelisted user
    modifier isWhitelistedUser(
        string memory mintType,
        uint8 limit,
        bytes memory sig
    ) {
        require(
            STANDARD_CURR_INDEX < MAX_SUPPLY,
            "contract reached the limit of max supply."
        );
        require(msg.sender != address(0), "Caller can't be null address");
        bytes32 message = keccak256(
            abi.encodePacked(mintType, msg.sender, limit)
        );
        require(
            recoverSigner(getETHSignedMessage(message), sig) ==
                whitelistingOwner,
            "signature validation failed or user is not whitelisted"
        );
        _;
    }

    // This function is used to get the ethereum signature of the message
    function getETHSignedMessage(
        bytes32 _messageHash
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n32",
                    _messageHash
                )
            );
    }

    // This function is used to mint standard NFTs when whitelisted round is open and address is whitelisted
    /*
     * @dev
     *
     * Requirements:
     *
     * `planetNo` should be in uin8. Example: 2.
     */
    function standardPreMint(
        uint8 planetNo,
        uint8 mintLimit,
        bytes memory sig
    ) external isWhitelistedUser("Standard", mintLimit, sig) {
        require(
            nftMintedCounts[msg.sender].standardMinted < mintLimit,
            "mint limit reached"
        );
        nftMintedCounts[msg.sender].standardMinted += 1;
        uint256 tokenId = STANDARD_CURR_INDEX++;
        uint16 metadataId = _planetsMetadata.setRandomTokenMetadata(
            planetNo,
            tokenId
        );
        _safeMint(msg.sender, tokenId);
        emit NFTMinted(
            "StandardWhitelisted",
            msg.sender,
            tokenId,
            metadataId,
            0
        );
    }

    // @dev This function is used to mint standard NFTs
    /*
     * @dev
     *
     * Requirements:
     *
     * `planetNo` should be in uin8. Example: 2.
     * `mintLimit` should be in uin8. Example: 2.
     * `sig` should be in bytes. Example: 0x4418f..........d43e6b174571b.
     */
    function standardMint(uint8 planetNo) external payable {
        require(msg.value >= PRICE_PER_MINT, "insuficient funds to mint NFT.");
        uint256 tokenId = STANDARD_CURR_INDEX++;
        uint16 metadataId = _planetsMetadata.setRandomTokenMetadata(
            planetNo,
            tokenId
        );
        _safeMint(msg.sender, tokenId);
        emit NFTMinted("Standard", msg.sender, tokenId, metadataId, msg.value);
    }

    // This function is used to mint gold NFTs by admin
    /*
     * @dev
     *
     * Requirements:
     *
     * `mintLimit` should be in uin8. Example: 2.
     * `sig` should be in bytes. Example: 0x4418f..........d43e6b174571b.
     */
    function goldMint(
        uint8 mintLimit,
        bytes memory sig
    ) external isWhitelistedUser("Gold", mintLimit, sig) {
        require(
            TOTAL_GOLD_MINTED < GOLD_MAX_SUPPLY,
            "all gold NFTs are minted."
        );
        require(
            TOTAL_GOLD_MINTED + mintLimit <= GOLD_MAX_SUPPLY,
            "amount exceeds the limit"
        );
        require(
            nftMintedCounts[msg.sender].goldMinted < mintLimit,
            "mint limit reached"
        );
        uint8 availableGoldNFTs = GOLD_MAX_SUPPLY - TOTAL_GOLD_MINTED;
        uint8 NftsToMint = mintLimit - nftMintedCounts[msg.sender].goldMinted;
        if (availableGoldNFTs >= NftsToMint) {
            nftMintedCounts[msg.sender].goldMinted += NftsToMint;
        } else {
            NftsToMint = availableGoldNFTs;
            nftMintedCounts[msg.sender].goldMinted += availableGoldNFTs;
        }
        for (uint8 i = 1; i <= NftsToMint; i++) {
            uint256 tokenId = GOLD_START_INDEX++;
            TOTAL_GOLD_MINTED++;
            _planetsMetadata.setTokenMetadataId(tokenId);
            _safeMint(msg.sender, tokenId);
            emit NFTMinted("Gold", msg.sender, tokenId, tokenId, 0);
        }
    }

    // This function is used to mint platinum NFTs by admin
    /*
     * @dev
     *
     * Requirements:
     *
     * `mintLimit` should be in uin8. Example: 2.
     * `sig` should be in bytes. Example: 0x4418f..........d43e6b174571b.
     */
    function platinumMint(
        uint8 mintLimit,
        bytes memory sig
    ) external isWhitelistedUser("Platinum", mintLimit, sig) {
        require(
            TOTAL_PLATINUM_MINTED < PLATINUM_MAX_SUPPLY,
            "all platinum NFTs are minted."
        );
        require(
            TOTAL_PLATINUM_MINTED + mintLimit <= PLATINUM_MAX_SUPPLY,
            "amount exceeds the limit."
        );
        require(
            nftMintedCounts[msg.sender].platinumMinted < mintLimit,
            "mint limit reached"
        );
        uint8 availablePlatinumNFTs = GOLD_MAX_SUPPLY - TOTAL_GOLD_MINTED;
        uint8 NftsToMint = mintLimit -
            nftMintedCounts[msg.sender].platinumMinted;
        if (availablePlatinumNFTs >= NftsToMint) {
            nftMintedCounts[msg.sender].platinumMinted += NftsToMint;
        } else {
            NftsToMint = availablePlatinumNFTs;
            nftMintedCounts[msg.sender].platinumMinted += availablePlatinumNFTs;
        }
        for (uint8 i = 1; i <= NftsToMint; i++) {
            uint256 tokenId = PLATINUM_START_INDEX++;
            TOTAL_PLATINUM_MINTED++;
            _planetsMetadata.setTokenMetadataId(tokenId);
            _safeMint(msg.sender, tokenId);
            emit NFTMinted("Platinum", msg.sender, tokenId, tokenId, 0);
        }
    }

    // Function to update the NFT price, can only be called by the owner
    /*
     * @dev
     *
     * Requirements:
     *
     * `_priceInWei` should be in wei. Example: 0.02 ether should be as 20000000000000000.
     */
    function setMintPrice(uint256 _priceInWei) external onlyOwner {
        PRICE_PER_MINT = _priceInWei;
    }

    // Function to set royalty which is paid to the given address
    /*
     * @dev
     *
     * Requirements:
     *
     * - `receiver` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     * - `feePercent` should be given as multiplied by 100. Example: 9.5% should be as 950.
     */
    function setRoyalty(
        address receiver,
        uint96 feePercent
    ) external onlyOwner {
        if (receiver == address(0)) {
            receiver = msg.sender;
        }
        _setDefaultRoyalty(receiver, feePercent);
    }

    // TODO: need to confirm either this function should be required or not
    // Function to set royalty for the specific tokenID
    /*
     * @dev
     *
     * Requirements:
     *
     * - `receiver` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     * - `feePercent` should be given as multiplied by 100. Example: 9.5% should be as 950.
     */
    function setTokenRoyalty(
        uint256 tokenId,
        address receiver,
        uint96 feePercent
    ) external onlyOwner {
        if (receiver == address(0)) {
            receiver = msg.sender;
        }
        _setTokenRoyalty(tokenId, receiver, feePercent);
    }

    // Function to update the platform address
    function setPlatformAddress(address platformAddress) external onlyOwner {
        require(platformAddress != address(0), "cannot set zero address");
        _platformAddress = address(platformAddress);
    }

    // Function to update the whitelisting owner address
    function setWhitelistingOwner(
        address _whitelistingOwner
    ) external onlyOwner {
        require(_whitelistingOwner != address(0), "cannot set zero address");
        whitelistingOwner = address(_whitelistingOwner);
    }

    // function to withdraw ethers to admin account or other acocunt
    function withdrawFunds(address to) external onlyOwner {
        require(to != address(0), "address can not be empty.");
        (bool success, ) = to.call{value: address(this).balance}("");
        require(success, "Withdrawal failed");
        emit FundsTransferred(to, address(this).balance);
    }

    // external function to add client with NFT tokenID
    function addClient(
        uint16 tokenId,
        uint256 clientsToAdd
    ) external onlyOwner {
        _requireOwned(tokenId);
        bytes32 value = bytes32(bytes(clientsToAdd.toString()));
        // Call the internal function to set the trait.
        DynamicTraits.setTrait(tokenId, clientCountKey, value);
    }

    // external function to add transaction count with NFT tokenID
    function addTransaction(
        uint16 tokenId,
        uint256 txsToAdd,
        uint256 txsAmtToAdd
    ) external onlyOwner {
        _requireOwned(tokenId);
        bytes32 txCount = bytes32(bytes(txsToAdd.toString()));
        bytes32 txVolume = bytes32(
            bytes(string(abi.encodePacked(txsAmtToAdd.toString(), " $")))
        );
        // Call the internal function to set the trait.
        DynamicTraits.setTrait(tokenId, txCountKey, txCount);
        DynamicTraits.setTrait(tokenId, txVolumeKey, txVolume);
    }

    function setTraitMetadataURI(string calldata uri) external onlyOwner {
        // Set the new metadata URI.
        _setTraitMetadataURI(uri);
    }

    function isUserWhitelisted(
        string memory mintType,
        uint256 limit,
        bytes memory sig
    ) external view returns (bool) {
        bytes32 message = keccak256(
            abi.encodePacked(mintType, msg.sender, limit)
        );
        require(
            recoverSigner(getETHSignedMessage(message), sig) ==
                whitelistingOwner,
            "signature validation failed or user is not whitelisted"
        );
        return true;
    }

    function pauseMinting() public onlyOwner {
        _pause();
    }

    function unpauseMinting() public onlyOwner {
        _unpause();
    }

    function setBaseTokenURI(string memory baseTokenURI) external onlyOwner {
        _baseTokenURI = baseTokenURI;
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function updateTokenURI(
        uint16 tokenId,
        string calldata newMetadataUri,
        bytes calldata sig
    ) external {
        require(
            _requireOwned(tokenId) == msg.sender,
            "you are not owner of the token."
        );
        require(isValidURI(newMetadataUri, sig), "signature validation failed");
        _tokenURIs[tokenId] = newMetadataUri;
        emit UpdateTokenURI(tokenId, newMetadataUri, block.timestamp);
    }

    // The following functions are overrides required by Solidity.
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal override(ERC721, ERC721Pausable) returns (address) {
        return super._update(to, tokenId, auth);
    }

    function tokenURI(
        uint256 tokenId
    ) public view override(ERC721) returns (string memory) {
        _requireOwned(tokenId);
        if (bytes(_tokenURIs[tokenId]).length > 0) {
            return _tokenURIs[tokenId];
        }
        return
            string(
                abi.encodePacked(
                    _baseURI(),
                    _planetsMetadata.getMetadataIdByToken(tokenId).toString(),
                    ".json"
                )
            );
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(ERC721, DynamicTraits, ERC2981) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function maxSupply() external pure returns (uint16) {
        return MAX_SUPPLY;
    }

    function totalMinted() external view returns (uint16) {
        return STANDARD_CURR_INDEX - 126;
    }

    // public function to get the minted count by planet
    function getMintedbyPlanet(uint8 planetNo) public view returns (uint256) {
        return
            NFTS_PER_PLANET -
            _planetsMetadata.getAvailableNFTsbyPlanet(planetNo);
    }

    function isValidURI(
        string memory word,
        bytes memory sig
    ) internal view returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(word));
        return (recoverSigner(message, sig) == _platformAddress);
    }

    function recoverSigner(
        bytes32 message,
        bytes memory sig
    ) internal pure returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            // First 32 bytes, after the length prefix
            r := mload(add(sig, 32))

            // Second 32 bytes
            s := mload(add(sig, 64))

            // Final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }
}
