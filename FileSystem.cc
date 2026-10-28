#include "FileSystem.h"

#include <stdexcept>
#include <cstring>
#include <sys/stat.h>
#include <cerrno>

void FileSystem::writeUInt16(
   unsigned char *buffer,
   int offset,
   uint16_t value
) {

   buffer[offset] =
      (value >> 8) & 0xFF;

   buffer[offset + 1] =
      value & 0xFF;
}

uint16_t FileSystem::readUInt16(
   const unsigned char *buffer,
   int offset
) {

   return
      ((uint16_t)buffer[offset] << 8)
      |
      buffer[offset + 1];
}

void FileSystem::writeUInt32(
   unsigned char *buffer,
   int offset,
   uint32_t value
) {

   buffer[offset] =
      (value >> 24) & 0xFF;

   buffer[offset + 1] =
      (value >> 16) & 0xFF;

   buffer[offset + 2] =
      (value >> 8) & 0xFF;

   buffer[offset + 3] =
      value & 0xFF;
}

uint32_t FileSystem::readUInt32(
   const unsigned char *buffer,
   int offset
) {

   return
      ((uint32_t)buffer[offset] << 24)
      |
      ((uint32_t)buffer[offset + 1] << 16)
      |
      ((uint32_t)buffer[offset + 2] << 8)
      |
      ((uint32_t)buffer[offset + 3]);
}

void FileSystem::writeProductBlock(
   unsigned char *buffer,
   const Product &product
) {

   if (product.name.empty()) {
      throw std::runtime_error(
         "FileSystem::writeProductBlock - empty product name"
      );
   }

   if (product.name.length() > 12) {
      throw std::runtime_error(
         "FileSystem::writeProductBlock - product name too long"
      );
   }

   if (product.location.length() > 63) {
      throw std::runtime_error(
         "FileSystem::writeProductBlock - location too long"
      );
   }

   if (product.description.length() > 128) {
      throw std::runtime_error(
         "FileSystem::writeProductBlock - description too long"
      );
   }

   memset(
      buffer,
      0,
      BLOCK_SIZE
   );

   buffer[0] = TYPE_PRODUCT;

   buffer[1] = 0;

   memcpy(
      &buffer[2],
      product.name.c_str(),
      product.name.length()
   );

   writeUInt32(
      buffer,
      14,
      product.stock
   );

   writeUInt32(
      buffer,
      18,
      product.price
   );

   buffer[22] =
      product.location.length();

   memcpy(
      &buffer[23],
      product.location.c_str(),
      product.location.length()
   );

   buffer[86] =
      product.description.length();

   memcpy(
      &buffer[87],
      product.description.c_str(),
      product.description.length()
   );

   writeUInt16(
      buffer,
      254,
      0
   );
}

Product FileSystem::readProductBlock(
   const unsigned char *buffer
) {

   if (buffer[0] != TYPE_PRODUCT) {
      throw std::runtime_error(
         "FileSystem::readProductBlock - invalid product block"
      );
   }

   Product product;

   char name[13];

   memcpy(
      name,
      &buffer[2],
      12
   );

   name[12] = '\0';

   product.name = name;

   product.stock =
      readUInt32(
         buffer,
         14
      );

   product.price =
      readUInt32(
         buffer,
         18
      );

   int locationLength =
      buffer[22];

   product.location =
      std::string(
         reinterpret_cast<const char *>(&buffer[23]),
         locationLength
      );

   int descriptionLength =
      buffer[86];

   product.description =
      std::string(
         reinterpret_cast<const char *>(&buffer[87]),
         descriptionLength
      );

   return product;
}

FileSystem::FileSystem(const std::string &filename) {

   this->filename = filename;

   // An existing inventory must never be overwritten automatically.
   struct stat fileInfo;
   const bool fileExists = stat(filename.c_str(), &fileInfo) == 0;
   if (!fileExists && errno != ENOENT) {
      throw std::runtime_error("FileSystem - could not access inventory: " + filename);
   }

   if (!fileExists) {
      // format() creates the file and initializes its header and root directory.
      // If a file exists but cannot be read, format() is intentionally not called.
      format();
      return;
   }

   this->disk.open(filename, std::ios::in | std::ios::out | std::ios::binary);
   if (!this->disk.is_open()) {
      throw std::runtime_error("FileSystem - could not open existing inventory: " + filename);
   }

   unsigned char header[BLOCK_SIZE];
   this->disk.read(reinterpret_cast<char*>(header), BLOCK_SIZE);
   if (!this->disk || header[0] != TYPE_HEADER ||
       std::memcmp(&header[2], "TIENDAFS", 8) != 0 ||
       readUInt16(header, 12) != BLOCK_SIZE ||
       readUInt16(header, 14) != TOTAL_BLOCKS ||
       readUInt16(header, 16) != ROOT_BLOCK) {
      throw std::runtime_error("FileSystem - invalid existing inventory: " + filename);
   }
   this->disk.clear();
}

FileSystem::~FileSystem() {

   if (this->disk.is_open()) {
      this->disk.close();
   }
}

void FileSystem::readBlock(
   uint16_t blockNumber,
   unsigned char *buffer
) {

   if (blockNumber >= TOTAL_BLOCKS) {
      throw std::runtime_error(
         "FileSystem::readBlock - invalid block number"
      );
   }

   this->disk.seekg(
      blockNumber * BLOCK_SIZE,
      std::ios::beg
   );

   this->disk.read(
      reinterpret_cast<char *>(buffer),
      BLOCK_SIZE
   );

   if (!this->disk) {
      throw std::runtime_error(
         "FileSystem::readBlock - read error"
      );
   }
}

void FileSystem::writeBlock(
   uint16_t blockNumber,
   const unsigned char *buffer
) {

   if (blockNumber >= TOTAL_BLOCKS) {
      throw std::runtime_error(
         "FileSystem::writeBlock - invalid block number"
      );
   }

   this->disk.seekp(
      blockNumber * BLOCK_SIZE,
      std::ios::beg
   );

   this->disk.write(
      reinterpret_cast<const char *>(buffer),
      BLOCK_SIZE
   );

   if (!this->disk) {
      throw std::runtime_error(
         "FileSystem::writeBlock - write error"
      );
   }

   this->disk.flush();
}

void FileSystem::format() {

   if (this->disk.is_open()) {
      this->disk.close();
   }

   this->disk.open(
      this->filename,
      std::ios::out |
      std::ios::binary |
      std::ios::trunc
   );

   if (!this->disk.is_open()) {
      throw std::runtime_error(
         "FileSystem::format - could not create file"
      );
   }

   unsigned char block[BLOCK_SIZE];

   memset(block, 0, BLOCK_SIZE);

   for (int i = 0; i < TOTAL_BLOCKS; i++) {

      this->disk.write(
         reinterpret_cast<char *>(block),
         BLOCK_SIZE
      );

      if (!this->disk) {
         throw std::runtime_error(
            "FileSystem::format - write error"
         );
      }
   }

   this->disk.close();

   this->disk.open(
      this->filename,
      std::ios::in |
      std::ios::out |
      std::ios::binary
   );

   if (!this->disk.is_open()) {
      throw std::runtime_error(
         "FileSystem::format - could not reopen file"
      );
   }

   // Crear bloque de cabecera
   unsigned char headerBlock[BLOCK_SIZE];
   memset(headerBlock, 0, BLOCK_SIZE);
   headerBlock[0] = TYPE_HEADER;
   headerBlock[1] = 0;
   const char filename[] = "TIENDAFS";
   std::memcpy(&headerBlock[2], filename, 8);
   writeUInt16(headerBlock, 10, 1);
   writeUInt16(headerBlock, 12, BLOCK_SIZE);
   writeUInt16(headerBlock, 14, TOTAL_BLOCKS);
   writeUInt16(headerBlock, 16, ROOT_BLOCK);
   writeUInt16(headerBlock, 18, 0);
   writeUInt16(headerBlock, 20, 0);
   headerBlock[22] = 0xC0;
   writeUInt16(headerBlock, 254, 0);
   writeBlock(0, headerBlock);

   // Crear bloque de directorio raíz
    unsigned char rootBlock[BLOCK_SIZE];
    memset(rootBlock, 0, BLOCK_SIZE);
    rootBlock[0] = TYPE_DIRECTORY;
    rootBlock[1] = 0;
    writeUInt16(rootBlock, 254, 0);
    writeBlock(ROOT_BLOCK, rootBlock);
}

bool FileSystem::isBlockUsed(uint16_t blockNumber) {

   if (blockNumber >= TOTAL_BLOCKS) {
      throw std::runtime_error(
         "FileSystem::isBlockUsed - invalid block number"
      );
   }

   unsigned char header[BLOCK_SIZE];

   readBlock(0, header);

   int byteIndex = blockNumber / 8;
   int bitIndex = blockNumber % 8;

   unsigned char mask = 1 << (7 - bitIndex);

   return (header[22 + byteIndex] & mask) != 0;
}

void FileSystem::setBlockUsed(
   uint16_t blockNumber,
   bool used
) {

   if (blockNumber >= TOTAL_BLOCKS) {
      throw std::runtime_error(
         "FileSystem::setBlockUsed - invalid block number"
      );
   }

   unsigned char header[BLOCK_SIZE];

   readBlock(0, header);

   int byteIndex = blockNumber / 8;
   int bitIndex = blockNumber % 8;

   unsigned char mask = 1 << (7 - bitIndex);

   if (used) {

      header[22 + byteIndex] |= mask;

   } else {

      header[22 + byteIndex] &= ~mask;
   }

   writeBlock(0, header);
}

uint16_t FileSystem::allocateBlock() {

   for (
      uint16_t blockNumber = 2;
      blockNumber < TOTAL_BLOCKS;
      blockNumber++
   ) {

      if (!isBlockUsed(blockNumber)) {

         setBlockUsed(
            blockNumber,
            true
         );

         return blockNumber;
      }
   }

   throw std::runtime_error(
      "FileSystem::allocateBlock - no free blocks"
   );
}

void FileSystem::freeBlock(uint16_t blockNumber) {

   if (blockNumber < 2) {
      throw std::runtime_error(
         "FileSystem::freeBlock - protected block"
      );
   }

   if (blockNumber >= TOTAL_BLOCKS) {
      throw std::runtime_error(
         "FileSystem::freeBlock - invalid block number"
      );
   }

   unsigned char emptyBlock[BLOCK_SIZE];

   memset(
      emptyBlock,
      0,
      BLOCK_SIZE
   );

   writeBlock(
      blockNumber,
      emptyBlock
   );

   setBlockUsed(
      blockNumber,
      false
   );
}

void FileSystem::writeDirectoryEntry(
   unsigned char *buffer,
   int offset,
   const DirectoryEntry &entry
) {

   if (entry.name.length() > 12) {
      throw std::runtime_error(
         "FileSystem::writeDirectoryEntry - name too long"
      );
   }

   memset(
      &buffer[offset],
      0,
      12
   );

   memcpy(
      &buffer[offset],
      entry.name.c_str(),
      entry.name.length()
   );

   writeUInt16(
      buffer,
      offset + 12,
      entry.blockNumber
   );
}

DirectoryEntry FileSystem::readDirectoryEntry(
   const unsigned char *buffer,
   int offset
) {

   DirectoryEntry entry;

   char name[13];

   memcpy(
      name,
      &buffer[offset],
      12
   );

   name[12] = '\0';

   entry.name = name;

   entry.blockNumber = readUInt16(
      buffer,
      offset + 12
   );

   return entry;
}

void FileSystem::createCategory(const std::string &name) {

   if (name.empty()) {
      throw std::runtime_error(
         "FileSystem::createCategory - empty name"
      );
   }

   if (name.length() > 12) {
      throw std::runtime_error(
         "FileSystem::createCategory - name too long"
      );
   }

   unsigned char root[BLOCK_SIZE];

   readBlock(ROOT_BLOCK, root);

   if (root[0] != TYPE_DIRECTORY) {
      throw std::runtime_error(
         "FileSystem::createCategory - invalid root directory"
      );
   }

   int entries = root[1];

   if (entries >= 18) {
      throw std::runtime_error(
         "FileSystem::createCategory - root directory full"
      );
   }

   for (int i = 0; i < entries; i++) {

      int offset = 2 + (i * 14);

      DirectoryEntry currentEntry =
         readDirectoryEntry(root, offset);

      if (currentEntry.name == name) {
         throw std::runtime_error(
            "FileSystem::createCategory - category already exists"
         );
      }
   }

   uint16_t categoryBlock = allocateBlock();

   unsigned char category[BLOCK_SIZE];

   memset(
      category,
      0,
      BLOCK_SIZE
   );

   category[0] = TYPE_DIRECTORY;
   category[1] = 0;

   writeUInt16(
      category,
      254,
      0
   );

   writeBlock(
      categoryBlock,
      category
   );

   DirectoryEntry newEntry;

   newEntry.name = name;
   newEntry.blockNumber = categoryBlock;

   int newEntryOffset =
      2 + (entries * 14);

   writeDirectoryEntry(
      root,
      newEntryOffset,
      newEntry
   );

   root[1] = entries + 1;

   writeBlock(
      ROOT_BLOCK,
      root
   );

   unsigned char header[BLOCK_SIZE];

   readBlock(0, header);

   uint16_t categoryCount =
      readUInt16(header, 18);

   categoryCount++;

   writeUInt16(
      header,
      18,
      categoryCount
   );

   writeBlock(
      0,
      header
   );
}

uint16_t FileSystem::findCategory(
   const std::string &name
) {

   unsigned char root[BLOCK_SIZE];

   readBlock(ROOT_BLOCK, root);

   if (root[0] != TYPE_DIRECTORY) {
      throw std::runtime_error(
         "FileSystem::findCategory - invalid root directory"
      );
   }

   int entries = root[1];

   for (int i = 0; i < entries; i++) {

      int offset = 2 + (i * 14);

      DirectoryEntry entry =
         readDirectoryEntry(
            root,
            offset
         );

      if (entry.name == name) {
         return entry.blockNumber;
      }
   }

   return 0;
}

void FileSystem::createProduct(
   const std::string &categoryName,
   const Product &product
) {

   uint16_t categoryBlock =
      findCategory(categoryName);

   if (categoryBlock == 0) {
      throw std::runtime_error(
         "FileSystem::createProduct - category not found"
      );
   }

   unsigned char category[BLOCK_SIZE];

   readBlock(
      categoryBlock,
      category
   );

   if (category[0] != TYPE_DIRECTORY) {
      throw std::runtime_error(
         "FileSystem::createProduct - invalid category directory"
      );
   }

   int entries = category[1];


   for (int i = 0; i < entries; i++) {

      int offset =
         2 + (i * 14);

      DirectoryEntry currentEntry =
         readDirectoryEntry(
            category,
            offset
         );

      if (currentEntry.name == product.name) {

         unsigned char existingProductBuffer[BLOCK_SIZE];

         readBlock(
            currentEntry.blockNumber,
            existingProductBuffer
         );

         Product existingProduct =
            readProductBlock(
               existingProductBuffer
            );

         existingProduct.stock +=
            product.stock;

         writeProductBlock(
            existingProductBuffer,
            existingProduct
         );

         writeBlock(
            currentEntry.blockNumber,
            existingProductBuffer
         );

         return;
      }
   }


   if (entries >= 18) {
      throw std::runtime_error(
         "FileSystem::createProduct - category directory full"
      );
   }

   uint16_t productBlock =
      allocateBlock();

   unsigned char productBuffer[BLOCK_SIZE];

   writeProductBlock(
      productBuffer,
      product
   );

   writeBlock(
      productBlock,
      productBuffer
   );


   DirectoryEntry newEntry;

   newEntry.name =
      product.name;

   newEntry.blockNumber =
      productBlock;

   int newEntryOffset =
      2 + (entries * 14);

   writeDirectoryEntry(
      category,
      newEntryOffset,
      newEntry
   );

   category[1] =
      entries + 1;

   writeBlock(
      categoryBlock,
      category
   );


   unsigned char header[BLOCK_SIZE];

   readBlock(
      0,
      header
   );

   uint16_t productCount =
      readUInt16(
         header,
         20
      );

   productCount++;

   writeUInt16(
      header,
      20,
      productCount
   );

   writeBlock(
      0,
      header
   );
}

uint32_t FileSystem::purchaseProduct(const std::string &categoryName, const std::string &productName, uint32_t quantity) {
   if (quantity == 0) throw std::invalid_argument("invalid purchase quantity");
   uint16_t categoryBlock = findCategory(categoryName);
   if (categoryBlock == 0) throw std::runtime_error("category not found");
   unsigned char category[BLOCK_SIZE];
   readBlock(categoryBlock, category);
   if (category[0] != TYPE_DIRECTORY) throw std::runtime_error("invalid category directory");
   for (int i = 0; i < category[1]; ++i) {
      DirectoryEntry entry = readDirectoryEntry(category, 2 + i * 14);
      if (entry.name != productName) continue;
      unsigned char buffer[BLOCK_SIZE];
      readBlock(entry.blockNumber, buffer);
      Product product = readProductBlock(buffer);
      if (product.stock < quantity) throw std::out_of_range("insufficient stock");
      product.stock -= quantity;
      writeProductBlock(buffer, product);
      writeBlock(entry.blockNumber, buffer);
      return product.stock;
   }
   throw std::runtime_error("product not found");
}

Product FileSystem::findProduct(
   const std::string &categoryName,
   const std::string &productName
) {

   uint16_t categoryBlock =
      findCategory(categoryName);

   if (categoryBlock == 0) {
      throw std::runtime_error(
         "FileSystem::findProduct - category not found"
      );
   }

   unsigned char category[BLOCK_SIZE];

   readBlock(
      categoryBlock,
      category
   );

   if (category[0] != TYPE_DIRECTORY) {
      throw std::runtime_error(
         "FileSystem::findProduct - invalid category directory"
      );
   }

   int entries =
      category[1];

   for (int i = 0; i < entries; i++) {

      int offset =
         2 + (i * 14);

      DirectoryEntry entry =
         readDirectoryEntry(
            category,
            offset
         );

      if (entry.name == productName) {

         unsigned char productBuffer[BLOCK_SIZE];

         readBlock(
            entry.blockNumber,
            productBuffer
         );

         return readProductBlock(
            productBuffer
         );
      }
   }

   throw std::runtime_error(
      "FileSystem::findProduct - product not found"
   );
}

std::vector<std::string> FileSystem::listCategories() {
   std::vector<std::string> result;
   unsigned char root[BLOCK_SIZE];
   readBlock(ROOT_BLOCK, root);
   if (root[0] != TYPE_DIRECTORY) {
      throw std::runtime_error("FileSystem::listCategories - invalid root directory");
   }
   int entries = root[1];
   for (int i = 0; i < entries; ++i) {
      DirectoryEntry entry = readDirectoryEntry(root, 2 + i * 14);
      result.push_back(entry.name);
   }
   return result;
}

std::vector<std::string> FileSystem::listProducts(const std::string &categoryName) {
   std::vector<std::string> result;
   uint16_t categoryBlock = findCategory(categoryName);
   if (categoryBlock == 0) {
      throw std::runtime_error("FileSystem::listProducts - category not found");
   }
   unsigned char category[BLOCK_SIZE];
   readBlock(categoryBlock, category);
   if (category[0] != TYPE_DIRECTORY) {
      throw std::runtime_error("FileSystem::listProducts - invalid category directory");
   }
   int entries = category[1];
   for (int i = 0; i < entries; ++i) {
      DirectoryEntry entry = readDirectoryEntry(category, 2 + i * 14);
      result.push_back(entry.name);
   }
   return result;
}
