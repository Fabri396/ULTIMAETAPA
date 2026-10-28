#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include <fstream>
#include <string>
#include <cstdint>
#include <vector>

#define BLOCK_SIZE 256 // tamano de bloque en bytes
#define TOTAL_BLOCKS 1024 // numero total de bloques en el sistema de archivos
#define ROOT_BLOCK 1

#define TYPE_FREE         0x00 // bloque libre
#define TYPE_HEADER       0x01 // bloque de cabecera
#define TYPE_DIRECTORY    0x02 // bloque de directorio
#define TYPE_PRODUCT      0x03 // bloque de producto
#define TYPE_CONTINUATION 0x04 // bloque de continuación

struct DirectoryEntry {
   std::string name;
   uint16_t blockNumber;
};

struct Product {

   std::string name;

   uint32_t stock;

   uint32_t price;

   std::string location;

   std::string description;
};

class FileSystem {

   private:

      std::fstream disk; // flujo de archivo para el disco virtual
      std::string filename; // nombre del archivo que representa el disco virtual

      void writeUInt16(
         unsigned char *buffer,
         int offset,
         uint16_t value
      );

      uint16_t readUInt16(
         const unsigned char *buffer,
         int offset
      );

      void writeUInt32(
         unsigned char *buffer,
         int offset,
         uint32_t value
      );

      uint32_t readUInt32(
         const unsigned char *buffer,
         int offset
      );

      bool isBlockUsed(uint16_t blockNumber);

      void setBlockUsed(
         uint16_t blockNumber,
         bool used
      );

      uint16_t allocateBlock();

      void freeBlock(uint16_t blockNumber);

      void writeDirectoryEntry(
         unsigned char *buffer,
         int offset,
         const DirectoryEntry &entry
      );

      DirectoryEntry readDirectoryEntry(
         const unsigned char *buffer,
         int offset
      );

      void writeProductBlock(
         unsigned char *buffer,
         const Product &product
      );
      
      Product readProductBlock(
         const unsigned char *buffer
      );

   public:

      FileSystem(const std::string &filename); // constructor que abre el archivo del disco virtual

      ~FileSystem(); // destructor que cierra el archivo del disco virtual

      void format();  //crea e inicializa el disco virtual con bloques libres y un bloque de cabecera

      void readBlock( // lee un bloque del disco virtual en un buffer
         uint16_t blockNumber,
         unsigned char *buffer
      );

      void writeBlock( // escribe un bloque del buffer en el disco virtual
         uint16_t blockNumber,
         const unsigned char *buffer
      );

      void createCategory(const std::string &name);

      uint16_t findCategory(const std::string &name);

      void createProduct(
         const std::string &categoryName,
         const Product &product
      );

      uint32_t purchaseProduct(const std::string &categoryName, const std::string &productName, uint32_t quantity);

      Product findProduct(
         const std::string &categoryName,
         const std::string &productName
      );

      std::vector<std::string> listCategories();

      std::vector<std::string> listProducts(
         const std::string &categoryName
      );      
};

#endif