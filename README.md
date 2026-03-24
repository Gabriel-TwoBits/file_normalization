# Português
## Relatório de Desenvolvimento

Este documento detalha o processo de extração, validação e higienização de dados de eventos de segurança. O objetivo principal do script foi ler um arquivo de log bruto (raw_security_events.txt), que possuía inconsistências de formatação, e gerar um arquivo limpo, padronizado e pronto para análise (security_events_cleaned.txt).

Abaixo, detalho as decisões de arquitetura, as regras de negócio aplicadas e os desafios técnicos enfrentados durante o desenvolvimento em C.
### 1. Regras Adotadas para Validação

Para garantir que apenas dados úteis e consistentes chegassem ao arquivo final, estabeleci um conjunto rigoroso de regras de validação:

- Integridade Estrutural da Linha: Antes mesmo de tentar ler os campos, o código verifica se a linha possui o mínimo de informações necessárias. A regra de corte foi: a linha precisa ter pelo menos 3 separadores (vírgula, ponto e vírgula ou pipe). Se não tiver, é considerada corrompida e nem entra na contagem de linhas válidas.

- Validação de Severidade (Severity): O sistema aceita apenas um escopo fechado de níveis de criticidade. Para ser válido, após a leitura, o campo precisa obrigatoriamente corresponder a: LOW, MED, MEDIUM, HIGH, CRIT ou CRITICAL.

- Validação de Status: Da mesma forma, o status do evento foi restrito aos valores lógicos do ciclo de vida de um incidente: OPEN, CLOSED, DONE, RESOLVED, INVESTIGATING, ANALYSIS ou IN_PROGRESS.

- Contagem de Falhas de Login: O campo failed_logins precisava ser estritamente numérico. Foi implementada uma checagem (usando isdigit) para garantir que, se o log trouxesse um caractere não numérico logo no início desse campo, o valor assumido por padrão seria 0.

### 2. Como os Dados Foram Tratados

Os logs originais eram bagunçados, misturando letras maiúsculas e minúsculas, com espaços sobrando, usando delimitadores diferentes (,, ;, |) e até formatos diferentes na mesma base (duas linhas vinham no formato chave=valor, outras apenas com os valores).

Para destruir essas inconsistências e deixar a base de uma forma agradável de tratar, realizei:

- Remoção de Espaços em Branco: A primeira etapa do tratamento em memória foi aplicar a função trimWhiteSpaces, que varre o conteúdo bruto e remove os espaços, evitando que um dado como " OPEN " fosse tratado de forma diferente de "OPEN".

- Conversão Universal para Maiúsculas: Criei uma função utilitária stringToUpper que converteu agressivamente os campos de ID, Source, Severity e Status para letras maiúsculas. Isso foi crucial para anular a sensibilidade a maiúsculas/minúsculas da linguagem C durante as comparações.

- Padronização de Abreviações e Sinônimos: Na Severidade e no Status, as abreviações e sinônimos, viraram uma coisa só, como MED para MEDIUM e DONE para CLOSED, como demonstrado em suas respectivas funções no código.

- Formatação de Saída: O arquivo final foi gravado no formato CSV estruturado, utilizando exclusivamente o ponto e vírgula (;) como delimitador, com um cabeçalho claro.
### 3. Como Registros Inválidos Foram Resolvidos

A estratégia adotada para lidar com os campos inválidos foi ignorá-los na leitura que passava de dados do arquivo para texto, e posteriormente, de texto para dados da struct, onde:

- A estrutura SecurityEvent possui uma flag chamada is_valid. Ao ler os dados e passá-los para o array de structs, todo registro nascia com is_valid = 1.

- Durante a etapa de padronização, se um registro apresentasse uma Severidade ou Status que não estivesse na lista de valores aceitos (mesmo após a conversão para maiúsculas e tratamento de sinônimos), a flag is_valid era rebaixada para 0.

- A Resolução: Na última etapa do programa, a função writeCleanFile itera sobre o array de eventos. Se ela encontra um evento com is_valid == 0, ela simplesmente aciona um continue e pula aquela iteração. O registro inválido morre na memória e não é gravado no arquivo de saída, garantindo que o log resultante seja 100% íntegro.

### 4. Principais Dificuldades Técnicas Encontradas

Esse desafio é particularmente fácil se eu pudesse ter feito tudo na força bruta, mas EU MESMO me sinto incomodado de ficar usando os tais "números mágicos" (apesar de ser muito moleza e eu ainda fazer com certeza frequência). Pra deixar tudo o mais dinâmco possível, eu me embarreirei com:

- Parsing Flexível com sscanf: Como o arquivo misturava linhas com identificadores (id=...) e linhas sem identificadores, além de múltiplos delimitadores imprevisíveis (,, ;, |), foi necessário construir format specifiers extremamente complexos no sscanf (como %*[^=]=%[^,;|\n]). Encontrar a sintaxe exata usando expressões regulares do C para capturar as strings corretamente e ignorar o não necessário, o que foi um saco e espero que não exista uma fórmula mágica melhor que eu não saiba.

- Ponteiros e Alocação Dinâmica de Memória: O tamanho do log dita o uso da memória, então evitei o erro comum de criar arrays estáticos gigantes na pilha(na verdade eu fiz isso e voltei atrás depois), o que causaria Stack Overflow em logs maiores. O desafio foi gerenciar o ponteiro do arquivo todo com malloc e alocar o array de SecurityEvent no Heap, garantindo que todos os free() fossem chamados no final para evitar vazamentos de memória.
  
- Comportamento do strtok: O uso do strtok para quebrar as linhas do arquivo em memória modifica a string original (inserindo caracteres nulos \0). Foi difícil entender bem a ordem das operações para não corromper o buffer de dados antes de conseguir extrair todas as informações de cada evento (deu Segmentation Fault muitas vezes, antes de dar certo).

# English
## Development Report

This document details the process of removing, validating, and cleaning security event data. The main objective of the script was to read a raw log file (raw_security_events.txt), which had formatting inconsistencies, and generate a clean, standardized file ready for analysis (security_events_cleaned.txt).

Below, we detail the architectural decisions, the business rules applied, and the technical challenges faced during development in C.

### 1. Rules Adopted for Validation

To ensure that only useful and consistent data reaches the final file, I established a rigorous set of validation rules:

- Line Structural Integrity: Before even attempting to read the fields, the code checks if the line has the minimum possible information. The cutoff rule was: the line must have at least 3 separators (comma, semicolon, or pipe). If it does not, it is considered corrupted and does not even enter the count of valid lines.

- Severity Validation: The system only accepts a closed scope of criticality levels. To be valid, after reading, the field must necessarily respond to: LOW, MED, MEDIUM, HIGH, CRIT, or CRITICAL.

- Status Validation: Similarly, the event status is restricted to the logical values ​​of an incident's lifecycle: OPEN, CLOSED, DONE, RESOLVED, INVESTIGATING, ANALYSIS, or IN_PROGRESS.

- Login Failure Count: The failed_logins field will be convenient and numerical. An innovative check (using `isdigit`) was implemented to ensure that if the log contained a non-numeric character at the beginning of a field, the default value would be 0.

### 2. How the data was handled

The logs were originally messy, mixing secret and lowercase letters, with extra spaces, using different delimiters (,, ;, |) and even different formats in the same database (two lines came in key=value format, others only with the values).

To eliminate these inconsistencies and make the database more manageable, I implemented the following:

- Removal of Whitespace: A first step in memory processing was applying the `trimWhiteSpaces` function, which scans the raw content and removes spaces, preventing data like "OPEN" from being treated differently from "OPEN".

- Universal Conversion to Uppercase: I created a utility function `stringToUpper` that harmfully converts the ID, Source, Severity, and Status fields to confidential letters. This was crucial to eliminate the C language's sensitivity to guards/lowercase during comparisons.

- Standardization of Abbreviations and Synonyms: In Severity and Status, abbreviations and synonyms became one and the same, such as MED for MEDIUM and DONE for CLOSED, as demonstrated in their respective functions in the code.

- Output Formatting: The final file was saved in structured CSV format, using only the semicolon (;) as a delimiter, with a clear header.

### 3. How Invalid Records Were Resolved

The strategy adopted to handle invalid fields was to bypass the reading process that converts data from the file to text, and subsequently, from text to struct data, where:

- The SecurityEvent structure has a flag called is_valid. When reading the data and passing it to the array of structs, every record is created with `is_valid = 1`.

- During the standardization stage, if a record presented a Severity or Status that was not in the list of accepted values ​​(even after conversion to nominal values ​​and handling of symbolic values), the `is_valid` flag was lowered to 0.

- The Solution: In the last stage of the program, the `writeCleanFile` function iterates over the array of events. If it finds an event with `is_valid == 0`, it simply triggers a `continue` and skips that iteration. The invalid record is removed from memory and not written to the output file, ensuring that the resulting log is 100% complete.

4. Main Technical Difficulties Encountered

This challenge is particularly easy if I could have done everything by brute force, but I MYSELF feel uncomfortable using those "magic numbers" (despite it being very easy and I still certainly do it frequently). To make everything as dynamic as possible, I ran into:

- Flexible Parsing with sscanf: As the file mixed lines with identifiers (id=...) and lines without identifiers, in addition to multiple unpredictable delimiters (,, ;, |), it was necessary to construct extremely complex format specifiers in sscanf (such as %*[^=]=%[^,;|\n]). Finding the exact syntax using C regular expressions to capture the strings correctly and ignore the unnecessary ones was a pain, and I hope there isn't a better magic formula that I don't know.

Pointers and Dynamic Memory Allocation: The log size dictates memory usage, so I avoided the common mistake of creating giant static arrays on the stack (in fact, I did this and reverted back).
