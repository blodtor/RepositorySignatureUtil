__XML sign service__

Подписание XML с помощью ключа из контейнера crypto pro

Java 17
Maven 3

Сборка: mvn package

Параметры:
api_version - версия API, необязательный, если не задан, будет использоваться по умолчанию: "1.0.3"
container_name - наименование контейнера криптопро
container_type - тип контейнера, необязательный, если не задан, будет использоваться по умолчанию: "HDImageStore"
container_pw - пароль контейнера, необязательный, если пустой
action - подписание\валидация (SIGN\VALIDATE), если не задан, будет использоваться по умолчанию: "SIGN"

Запуск
java -jar sign-service-1.0.0-jar-with-dependencies.jar "message=1.xml" "action=SIGN" "container_name=XXXXXXXXXXXX"
java -jar sign-service-1.0.0-jar-with-dependencies.jar "message=1.xml.signed.xml" "action=VALIDATE"

В папке bin есть собранное приложение и примеры xml
файл 1.xml - исходное сообщение
файл 1.xml.signed.xml - пример подписанного сообщения

База знаний КриптоПро https://support.cryptopro.ru/index.php?/Knowledgebase/List
AltLinux Wiki - установка сертфиката https://www.altlinux.org/КриптоПро#Установка_сертификата
Документация КриптоПро: https://docs.cryptopro.ru/