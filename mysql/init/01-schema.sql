-- Sin este SET NAMES el cliente que ejecuta los scripts de init interpreta
-- el archivo como latin1 y "María García" queda guardado como "MarÃ­a GarcÃ­a".
-- Es el bug clásico cuando los datos de prueba tienen acentos.
SET NAMES utf8mb4;

-- Datos de negocio MOCK para la POC.
--
-- Importante: todos los PAN de abajo son números de prueba públicos de las
-- marcas (Visa/Mastercard/Amex/Discover). Pasan Luhn — que es lo que necesita
-- Presidio para detectarlos como CREDIT_CARD — pero no son tarjetas reales.
-- Los DNI/CUIT/CBU son inventados y siguen el formato argentino.

CREATE TABLE clientes (
  id           INT PRIMARY KEY,
  nombre       VARCHAR(80)  NOT NULL,
  email        VARCHAR(120) NOT NULL,
  dni          VARCHAR(12)  NOT NULL,
  cuit         VARCHAR(16)  NOT NULL,
  telefono     VARCHAR(24)  NOT NULL,
  direccion    VARCHAR(140) NOT NULL,
  tarjeta      VARCHAR(20)  NOT NULL,   -- PCI
  cbu          VARCHAR(24)  NOT NULL,   -- PCI-adyacente
  saldo        DECIMAL(12,2) NOT NULL,
  segmento     VARCHAR(20)  NOT NULL,
  estado       VARCHAR(20)  NOT NULL,
  alta         DATE         NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO clientes VALUES
 (1,'María García','maria.garcia@ejemplo.com.ar','30111222','20-30111222-3','+54 11 4555-1001','Av. Corrientes 1234, CABA','4111111111111111','0070099530004512345678',152340.75,'premium','activo','2021-03-14'),
 (2,'Juan García','juan.garcia@ejemplo.com.ar','28944310','20-28944310-7','+54 11 4555-1002','Av. Rivadavia 980, CABA','5555555555554444','0170099540000012345679',  8320.10,'estandar','activo','2022-07-01'),
 (3,'Lucía Fernández','lucia.fernandez@ejemplo.com.ar','33566401','27-33566401-4','+54 11 4555-1003','Calle Falsa 123, Vicente López','378282246310005','0290099540000012345680', 45900.00,'premium','activo','2020-11-23'),
 (4,'Pablo Sosa','pablo.sosa@ejemplo.com.ar','31208877','20-31208877-1','+54 11 4555-1004','San Martín 455, Quilmes','6011111111111117','0110099540000012345681',  1200.50,'estandar','moroso','2023-02-09'),
 (5,'Carla Romero','carla.romero@ejemplo.com.ar','35770912','27-35770912-9','+54 11 4555-1005','Belgrano 77, Rosario','4012888888881881','0720099540000012345682', 67800.25,'premium','activo','2019-06-30'),
 (6,'Diego Pérez','diego.perez@ejemplo.com.ar','29433120','20-29433120-5','+54 11 4555-1006','Mitre 3200, La Plata','5105105105105100','0150099540000012345683', 23410.00,'estandar','activo','2022-01-18'),
 (7,'Sofía Gutiérrez','sofia.gutierrez@ejemplo.com.ar','36120455','27-36120455-2','+54 11 4555-1007','Alsina 612, Córdoba','4111111111111111','0070099540000012345684', 99120.80,'premium','activo','2021-09-05'),
 (8,'Martín López','martin.lopez@ejemplo.com.ar','27880133','20-27880133-6','+54 11 4555-1008','Urquiza 145, Mendoza','5555555555554444','0170099540000012345685',   540.00,'estandar','inactivo','2018-04-12'),
 (9,'Valentina Díaz','valentina.diaz@ejemplo.com.ar','37455201','27-37455201-8','+54 11 4555-1009','Sarmiento 2290, CABA','378282246310005','0290099540000012345686', 18765.40,'estandar','activo','2023-05-27'),
(10,'Nicolás García','nicolas.garcia@ejemplo.com.ar','32001455','20-32001455-0','+54 11 4555-1010','Lavalle 870, CABA','6011111111111117','0110099540000012345687',311200.00,'corporativo','activo','2017-10-02'),
(11,'Agustina Molina','agustina.molina@ejemplo.com.ar','34209188','27-34209188-5','+54 11 4555-1011','Güemes 410, Salta','4012888888881881','0720099540000012345688',  7430.65,'estandar','activo','2024-01-15'),
(12,'Federico Ruiz','federico.ruiz@ejemplo.com.ar','30677214','20-30677214-9','+54 11 4555-1012','Moreno 55, Bahía Blanca','5105105105105100','0150099540000012345689', 52100.90,'premium','moroso','2020-08-19');

CREATE INDEX idx_clientes_nombre ON clientes (nombre);
