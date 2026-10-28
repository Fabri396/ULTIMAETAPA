#include "FileSystem.h"

#include <iostream>

int main() {

   FileSystem fs("tienda.dat");

   fs.format();

   // Crear categoria
   fs.createCategory("ropa");

   // Crear primer producto
   Product camisa;

   camisa.name = "camisa";
   camisa.stock = 25;
   camisa.price = 12500;
   camisa.location = "Pasillo 3";
   camisa.description = "Camisa de algodon";

   fs.createProduct(
      "ropa",
      camisa
   );

   // Buscar producto despues de crearlo
   Product encontrado1 =
      fs.findProduct(
         "ropa",
         "camisa"
      );

   std::cout << "=== PRIMERA CREACION ===" << std::endl;

   std::cout << "Nombre: "
             << encontrado1.name
             << std::endl;

   std::cout << "Stock: "
             << encontrado1.stock
             << std::endl;

   std::cout << "Precio: "
             << encontrado1.price
             << std::endl;

   std::cout << "Ubicacion: "
             << encontrado1.location
             << std::endl;

   std::cout << "Descripcion: "
             << encontrado1.description
             << std::endl;


   // Agregar mas camisas
   Product masCamisas;

   masCamisas.name = "camisa";
   masCamisas.stock = 10;
   masCamisas.price = 12500;
   masCamisas.location = "Pasillo 3";
   masCamisas.description = "Camisa de algodon";

   fs.createProduct(
      "ropa",
      masCamisas
   );


   // Buscar nuevamente
   Product encontrado2 =
      fs.findProduct(
         "ropa",
         "camisa"
      );

   std::cout << "\n=== DESPUES DE AGREGAR 10 ==="
             << std::endl;

   std::cout << "Nombre: "
             << encontrado2.name
             << std::endl;

   std::cout << "Stock: "
             << encontrado2.stock
             << std::endl;

   std::cout << "Precio: "
             << encontrado2.price
             << std::endl;

   std::cout << "Ubicacion: "
             << encontrado2.location
             << std::endl;

   std::cout << "Descripcion: "
             << encontrado2.description
             << std::endl;

   return 0;
}