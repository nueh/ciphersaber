RC4 wird in der zweiten Auflage von Bruce Schneier: Applied Cryptography
beschrieben. Im Internet ist die Beschreibung als [IETF Standard-Entwurf
namens
ARCFOUR](http://search.ietf.org/internet-drafts/draft-kaukonen-cipher-arcfour-03.txt)
zu finden oder durch eine Suche nach "rc4 source" bei einer
Suchmaschine. Es folgt die Beschreibung in Deutsch:

RC4 benutzt zwei Felder mit 8 Bit Bytes. Das "Status"-Feld ist 256
Bytes lang und enthält eine Permutation der Zahlen von 0 bis 255. Das
\"Schlüssel\"-Feld hat eine beliebige Länge bis 256 Bytes. Alle
Variablen sind 8 Bit groß und alle Additionen werden modulo 256
durchgeführt.

RC4 besteht aus zwei Phasen: Schlüsselkonstruktion und Chiffrierung.

Die Schlüsselkonstruktion geschieht nur einmal pro Nachricht. Zunächst
wird das Statusfeld initialisiert, so daß jedes Element seinen Index
enthält (Element 0 enthält 0, Element 1 enthält 1 ...).

Das Statusfeld wird dann mit 256 Mischoperationen in einer Schleife
durchmischt. Die Schleife läßt die Variable i die Werte von 0 bis 255
durchlaufen. Die Variable j hat initial den Wert Null. Jede
Mischoperation besteht aus zwei Schritten:

-   Addiere den Inhalt des i-ten Elements des Statusfeldes und das
    n-te Element des Schlüsselfeldes zur Variablen j, wobei n gleich i
    modulo der Länge des Schlüssels ist.
-   Vertausche das i-te und das j-te Elements des Statusfeldes.

Nachdem die Mischschleife beendet ist, werden i und j auf Null
gesetzt.

Während der Chiffrierung werden die folgenden Schritte für jedes Byte
der Nachricht durchgeführt:

-   Die Variable i wird um 1 erhöht.
-   Der Inhalt des i-ten Elements des Statusfeldes wird zu j addiert.
-   Das i-te und j-te Element des Statusfeldes werden vertauscht und
    sie werden zu einem neuen Wert n addiert.
-   Das Ausgabe-Byte wird durch eine bitweise XOR-Operation des n-ten
    Elements des Statusfeldes mit dem Byte der Nachricht berechnet.

Die gleichen Schritte werden für Chiffrierung und Dechiffrierung
durchgeführt.

Bei CipherSaber besteht das RC4 Schlüsselfeld aus dem Schlüssel des
Benutzers gefolgt vom 10 Byte langen Initialisierungsvektor IV.

-   Bei der Verschlüsselung wird ein neuer IV zufällig erzeugt und an
    den Anfang der Nachricht geschrieben. Der IV wird bei der
    Erzeugung des Statusfeldes an den Benutzerschlüssel angehängt (und
    verlängert diesen damit um 10 Bytes).
-   Bei der Entschlüsselung werden die ersten 10 Bytes der Nachricht
    als IV eingelesen und an den Benutzerschlüssel angehängt.

Das ist schon alles!
