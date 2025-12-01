- Introduccion:
    El codigo parece funcionar correctamente. En caso afirmativo, aun asi, tengo algunas dudas.

- Preguntas sobre la implementacion:
1. Paquete "drbg":
    1. El codigo original utiliza el generador de numeros pseudo-aleatorios del sistema operativo a partir de
    la funcion "os.urandom(self.seed_length)". No obstante, este algoritmo requiere la utilizacion de un
    generador aleatorio aprobado por el NIST, indicado en la pagina 16 del FIPS 203. Por ejemplo, el generador
    "AES256_CTR_DRBG" es un "RBG" aprobado y, por tanto, se puede utilizar. Ademas, esta implementado en el
    codigo original como opcion a utilizar. En este caso, empleo el generador del sistema operativo, como esta 
    por defecto, o lo cambio por el otro generador aprobado con la funcion "set_drbg_seed" de "ml_kem".

2. Paquete "ml-kem":
    1. La CCN recomienda usar longitudes de hash de al menos 256 bits. No obstante, este codigo emplea para el
    algoritmo "XOF" una funcion SHAKE128. Existe algun problema o conflicto entre la implementacion indica por
    el NIST y la recomendacion de la CCN. RESPUESTA: NO.

3. Paquete "polynomials":
    1. Las funciones "ntt_sample", "cbd", "decode" y "encode" parecen seguir los algoritmos de la implementacion
    de CRYSTAL-KYBER en vez de la implementacion especificada en el documento FIPS 203. Despues de mirar las dos
    especificaciones, desconozco si tienen un funcionamiento equivalente. Intento cambiar las funciones o, por
    el contrario, dejo las funciones vigentes.

    2. Dudo que la funcion "from_ntt" de la clase "PolynomialKyberNTT" este bien implementada. Esta funciona
    esta en la linea 429 del codigo "polynomials.py".

    3. El estandar especifica dos algoritmos (Algorithm 3 & 4) para cambiar entre bytes y bits. No obstante,
    el codigo emplea dos funciones diferentes que son de la clase "int": "from_bytes" & "to_bytes". Por tanto,
    considerando esto, debo cambiar las funcionas por las especificadas en el estandar o dejo las funciones
    implementadas en el codigo original.
    
4. General:   
    1. La gran mayoria de agencias de ciberseguridad recomiendan una implementacion hibrida de algoritmos de
    cifrado pre-cuanticos y post-cuanticos hasta que se den pruebas teoricas firmes de la seguridad de los
    algoritmos post-cuanticos estandarizados. Por tanto, en esta implementacion, se deberia implementar el
    algoritmo "ML-KEM" con otro algoritmo clasico de forma combinada.
    
    2. A parte del algoritmo "ML-KEM", existe un algoritmo alternativo basado en reticulos no estructurados
    conocido como "Frodo-KEM", el cual tiene peor rendimiento pero ofrece una mayor seguridad. Aunque el
    NIST lo descartase, todavia lo considera como una opcion conservadora y la CCN lo recomienda y considera.
