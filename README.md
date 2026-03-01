# LAB 4: 

## Règles de sécurité et périmètre: 

- Analysez uniquement des APK autorisés (fournis par l'enseignant ou générés par vos soins).
- N'utilisez pas d'applications tierces du Play Store sans autorisation explicite.
- Ne tentez pas d'exploiter des vulnérabilités découvertes.
- Travaillez uniquement avec des données fictives.
- Ce lab est strictement pédagogique et vise à comprendre les mécanismes de sécurité.

## Définitions:

- **APK (Android Package)** : format d'archive contenant tous les éléments d'une application Android (code, ressources, manifeste, signatures)
- **DEX (Dalvik Executable)** : format de bytecode utilisé par la machine virtuelle Android (Dalvik/ART)
- **Manifest** : fichier XML déclarant les composants, permissions et configurations d'une application Android
- **Décompilation** : processus de conversion du bytecode en code source lisible (approximatif)
- **Obfuscation** : technique visant à rendre le code difficile à comprendre (renommage de variables, restructuration)
- **Exported** : attribut indiquant si un composant Android est accessible depuis d'autres applications
- **Signature** : mécanisme cryptographique garantissant l'intégrité.

**TODO:** ADD the three screenshots.

## Obtenir APK:

  ### Vérifiez que l'APK est bien une archive ZIP: 

 ![apks](https://github.com/user-attachments/assets/36c6a7c8-5fb5-4676-9e3b-eea989b4c1cb)

  ### Listez le contenu de l'APK: 

![apk content](https://github.com/user-attachments/assets/14295f51-3af9-4f3b-a2ee-2da1922f35d5)

  ### Integrité d'APK:

  ![apk's sha](https://github.com/user-attachments/assets/9d52bfc3-d06e-42b1-a421-ca8e2a2415e5)
  
## Exploration de la structure de l'APK:

### resources/AndroidManifest.xml: 

![manifeste](https://github.com/user-attachments/assets/07daec94-f21c-40cf-8c5b-30da66c507b2) 

### resources/res/values/strings.xml:

![strings.xml](https://github.com/user-attachments/assets/1a92a92b-d39e-47da-9814-7db900dcf522) 


### sg.vantagepoint.uncrackable1: 

![main](https://github.com/user-attachments/assets/52a2b94a-6eeb-46f4-887e-c38cd8ee6d9d)


##  $${\color{red}Analyse le manifeste:}$$

- $${\color{red}Package principal:}$$ **owasp.mstg.uncrackable1**.
- $${\color{red}versionName:}$$ **1.0**
- $${\color{red}minSDK:}$$ **19** 
- $${\color{red}targetSDK:}$$ **28**
- $${\color{red}MainActivity:}$$ **android:name="sg.vantagepoint.uncrackable1.MainActivity**
- $${\color{red}intent-filter:}$$ `<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>`
- Il n'y a ni `sh android:usesCleartextTraffic="true"` ni `android:debuggable="true"` 

## Analyse des ressources importantes(*ex strings.xml...*):

### res/values/strings.xml 

~~~ xml

<resources>
    <style name="AppTheme" parent="@android:style/Theme.Holo.Light.DarkActionBar">
    </style>
</resources>

~~~

### res/values/styles.xml 

~~~ xml

<resources>
    <string name="action_settings">Uncrackable1</string>
    <string name="app_name">Uncrackable1</string>
    <string name="button_verify">Verify</string>
    <string name="edit_text">Enter the Secret String</string>
    <string name="thanks">With special thanks to Bernhard Mueller for creating the app. Now maintained by the MSTG project. Want more? Check the MSTG playground!</string>
</resources>

~~~

## Identification des informations sensibles codées en dur dans l'application.

### url & endpoint:

Il y a certains fichiers qui sont codés en dur:

**TODO** : ADD PIC OF FINDING/SEARCHING

~~~ Java

  public static boolean c() {
        for (String str : new String[]{"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"}) {
            if (new File(str).exists()) {
                return true;
            }
        }
        return false;
    }

~~~

### Informations d'authentification:

![](https://github.com/user-attachments/assets/c9564daa-9620-4fc2-9ea9-ff28cdcd6036)

### indicateurs de mode de développement:

![](https://github.com/user-attachments/assets/2a39dd12-b720-4598-85d9-5c82c05d0e9d)

![](https://github.com/user-attachments/assets/89a1a645-e4f3-4cf0-b877-df0cd18d7e5a)


**TODO** ADD DESCRIPTION (ANS FROM QUEST 5) 

### Grille de sévérité :
* **Faible :** Information publique ou non sensible.
* **Moyen :** Information sensible à impact limité (clés de test).
* **Élevé :** Secret critique (clés de production, algorithmes de chiffrement).

### Observations documentées :

| Valeur / Pattern trouvé | Emplacement (Fichier, Classe, Méthode) | Niveau de Risque | Description du problème |
| :--- | :--- | :--- | :--- |
| **AES/ECB/PKCS7Padding** | `sg.vantagepoint.a.a` (Méthode `a`) | **Élevé** | Utilisation du mode **ECB** pour le chiffrement AES. Ce mode est non sécurisé car il n'utilise pas de vecteur d'initialisation (IV), rendant les motifs de données prévisibles. |
| **Indicateurs de Root (Fichiers)** | Classe `c` (Méthode `c`) | **Faible** | Liste de chemins vers des binaires de super-utilisateur (`Superuser.apk`, `daemonsu`). Ces chemins sont codés en dur, ce qui facilite leur contournement. |
| **Indicateur "test-keys"** | Classe `c` (Méthode `b`) | **Faible** | Vérification de la chaîne `test-keys` dans `Build.TAGS`. Utilisé pour détecter les signatures de ROM personnalisées. |
| **Vérification du Débogage** | `MainActivity` (Méthode `onCreate`) | **Moyen** | Appel à `b.a(getApplicationContext())` pour détecter si l'application est en mode debug. Si vrai, un message d'alerte s'affiche. |
| **Logique d'Anti-Tampering** | `MainActivity` (Méthode `onCreate`) | **Élevé** | Si les méthodes de détection de root (`c.a`, `c.b`, `c.c`) renvoient vrai, l'application bloque l'accès avec le message "Root detected!". |

---

## 4. Conclusion sur le Secret Hardcodé
La classe `sg.vantagepoint.a.a` agit comme un utilitaire de déchiffrement. Le premier paramètre `bArr` représente la clé secrète. Puisque cette méthode est appelée dynamiquement lors de la vérification, la clé est nécessairement stockée ailleurs dans le code source sous forme de tableau d'octets statique, ce qui constitue une vulnérabilité majeure de "Hardcoded Secret".


