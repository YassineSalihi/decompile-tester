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


##  $${\color{red}Analyse  du manifeste:}$$

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

### 4. Conclusion sur le Secret Hardcodé
La classe `sg.vantagepoint.a.a` agit comme un utilitaire de déchiffrement. Le premier paramètre `bArr` représente la clé secrète. Puisque cette méthode est appelée dynamiquement lors de la vérification, la clé est nécessairement stockée ailleurs dans le code source sous forme de tableau d'octets statique, ce qui constitue une vulnérabilité majeure de "Hardcoded Secret".

## Convertir DEX → JAR avec dex2jar: 

**Objectif**: Transformer le bytecode Android en format JAR pour une analyse alternative.

![](https://github.com/user-attachments/assets/5541c3d7-c8d5-43e0-a85b-2f84c220659b)

> [!NOTE]
> installing dex2jar 
> ~~~sh 
>
>  sudo apt install dex2jar 
>
> ~~~~

Voila la commande de convertission:

![](https://github.com/user-attachments/assets/b69b44af-ed22-4071-8950-6473a314b9a9)

## Comparaison JADX vs JD-GUI:

Choisir notre APK pour JD-GUI:
![](https://github.com/user-attachments/assets/ffb1034a-a7d1-4be8-b77d-5503fd918272)

Structure d'APK:
![](https://github.com/user-attachments/assets/d39bd421-250b-4fdc-85e3-dd2a373b591e)

| Aspect | JADX GUI | JD-GUI |
| --------------- | --------------- | --------------- |
| Navigation | Structure complète | Juste les classes  |
| Ressources | Ressources sont disponibles | Absence des ressources |

---

# Rapport d'Analyse Statique - Uncrackable1(Tâche finale)

## A) Informations générales
- **Titre :** Analyse statique de l'application OWASP Uncrackable Level 1
- **Date :** 1 mars 2026
- **Analyste :** [SALIHI Yassine]
- **APK :** `uncrackable1.apk`
- **Version :** 1.0
- **Provenance :** Lab 4 - OWASP Mobile Security Testing Guide (MSTG)
- **Outils utilisés :** JADX GUI v1.4.7, dex2jar v2.1, JD-GUI v1.6.6

## B) Résumé exécutif
Cette analyse statique a révélé **3** vulnérabilités majeures dans l'application **Uncrackable1**.
Les principales préoccupations concernent l'utilisation d'un **mode de chiffrement obsolète (AES-ECB)**, la présence de **secrets cryptographiques codés en dur** et des mécanismes d'auto-protection (Anti-Root/Anti-Debug) facilement identifiables.

Le niveau de risque global est évalué comme **Élevé**.

**Actions prioritaires recommandées :**
1. Remplacer le mode AES-ECB par AES-GCM avec une gestion dynamique des clés.
2. Implémenter le **Android Keystore System** pour éviter le stockage de clés en clair dans le code.
3. Obfusquer les chaînes de caractères sensibles et renforcer les contrôles d'intégrité.

---

## C) Constats détaillés

### Constat #1 : Utilisation d'un mode de chiffrement non sécurisé (ECB)
**Sévérité :** Élevée  
**Description :** L'application initialise un objet Cipher avec le mode `AES/ECB/PKCS7Padding`. Le mode ECB (Electronic Codebook) est considéré comme non sécurisé car il n'utilise pas de vecteur d'initialisation (IV), ce qui rend les données chiffrées prévisibles.  
**Localisation :** Fichier : `sg.vantagepoint.a.a`, Méthode : `a(byte[] bArr, byte[] bArr2)`  
**Impact potentiel :** Un attaquant pourrait effectuer une analyse de motifs sur le texte chiffré pour déduire des informations sensibles sans posséder la clé.  
**Remédiation recommandée :** Utiliser un mode de chiffrement authentifié comme **AES-GCM**.



### Constat #2 : Secrets et clés cryptographiques codés en dur
**Sévérité :** Élevée  
**Description :** La clé de déchiffrement (`bArr`) est passée sous forme de tableau d'octets statique. Bien que la méthode soit isolée, l'appelant fournit une clé fixe qui peut être extraite via une recherche de références (Find Usages) dans le bytecode.  
**Localisation :** Classe `sg.vantagepoint.uncrackable1.MainActivity` (Logique de vérification)  
**Impact potentiel :** Un attaquant peut récupérer la "Secret String" originale en quelques secondes en réutilisant la clé extraite.  
**Remédiation recommandée :** Ne jamais coder de clés en dur. Utiliser une dérivation de clé à partir d'un secret utilisateur ou le stockage sécurisé matériel (TEE/Keystore).

### Constat #3 : Détection de Root et Debug contournable
**Sévérité :** Moyenne  
**Description :** L'application contient une liste de chemins de fichiers système (`Superuser.apk`, `daemonsu`, etc.) et des vérifications de `Build.TAGS` pour bloquer l'exécution sur les téléphones rootés.  
**Localisation :** Classe `sg.vantagepoint.a.c`, Méthodes `a()`, `b()` et `c()`  
**Impact potentiel :** Ces vérifications sont purement logicielles et peuvent être neutralisées par injection de code (Frida) ou par modification du bytecode (Smali patching).  
**Remédiation recommandée :** Utiliser des solutions d'attestation externe comme **Play Integrity API**.

---

## D) Annexes

### Permissions demandées
- `android.permission.INTERNET` (Absente par défaut, mais vérifiée via Manifest)

### Composants exportés
- **Activity :** `sg.vantagepoint.uncrackable1.MainActivity` (Point d'entrée LAUNCHER)

### Comparaison des outils utilisés
| Outil | Forces | Faiblesses |
| :--- | :--- | :--- |
| **JADX GUI** | Décompilation précise, accès direct aux ressources (XML, images). | Parfois lent sur de très gros fichiers. |
| **dex2jar / JD-GUI** | Permet une analyse de type "Java Standard", utile pour les outils tiers. | Ne traite pas les fichiers de ressources (Manifest, Strings). |

---
**Rapport généré par :** *SALIHI Yassine*


