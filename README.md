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


## Analyse le manifeste: $${\color{red}Analyse le manifeste: }$$

- $${\color{red}Package principal:}$$ **owasp.mstg.uncrackable1**.
- $${\color{red}versionName:}$$ **1.0**
- $${\color{red}minSDK:}$$ **19** 
- $${\color{red}targetSDK:}$$ **28**
- $${\color{red}MainActivity:}$$ **android:name="sg.vantagepoint.uncrackable1.MainActivity**
- $${\color{red}intent-filter:}$$ `<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>`
- Il n'y a ni `sh android:usesCleartextTraffic="true"` ni `android:debuggable="true"` 


































































