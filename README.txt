KAMETI - LIVE BACKEND PROJECT (Firebase)
=========================================
Isme kya hai
 public/      -> app ka frontend (website + PWA)
 functions/   -> backend (OTP login 2 min, profile, UPI verify, groups, draw, late fee, reminders)
 firestore.rules -> database ki suraksha: client sirf apna data PADH sakta hai, likhna sirf backend se
 Edit/delete sirf group ke admin (owner) ko, ye server par check hota hai.

Pehle se chahiye
 - Node.js 20, Google account
 - npm install -g firebase-tools   ->  firebase login

STEP 1: Firebase project
 1. console.firebase.google.com par naya project banayein.
 2. Billing plan "Blaze" (pay-as-you-go) chalu karein (Cloud Functions ke liye zaroori; chhote use mein lagbhag free).
 3. Build > Authentication > Get started > Sign-in method mein ye DO provider Enable karein:
      - Google
      - Phone  (mobile OTP ke liye, Firebase khud SMS bhejta hai)
    Email OTP hamara apna system hai (free SMTP se), uske liye kuch enable nahi karna.
    Authentication > Settings > Authorized domains mein apna domain jodein.
 4. Build > Firestore Database > Create (location: asia-south1 Mumbai).
 5. Project settings > Your apps > Web (</>) app banayein, jo config mile wo public/config.js mein paste karein.
 6. .firebaserc mein project id likhein.

STEP 2: Secrets (email aur UPI ke liye)
 firebase functions:secrets:set SMTP_URL      (free option: Gmail App Password ke saath
                                               smtps://aapka@gmail.com:APP_PASSWORD@smtp.gmail.com:465 ; roz lagbhag 500 email)
 firebase functions:secrets:set RAZORPAY_KEY
 firebase functions:secrets:set RAZORPAY_SECRET
 Testing ke liye kisi bhi secret mein "x" daal sakte hain jab tak DEMO_MODE=true ho.

 MOBILE OTP KA KHARCHA (Firebase Phone Auth):
 - Ye Blaze plan par chalta hai. Roz ke pehle 10 SMS free, uske baad India mein lagbhag $0.07 (~Rs 6) per SMS (Firebase pricing page par taaza rate dekh lein).
 - Bilkul free testing: Authentication > Sign-in method > Phone > "Phone numbers for testing" mein 10 tak fake number aur fixed OTP daalein.
 - Firebase ke SMS code ki expiry Firebase tay karta hai (2 minute ka rule sirf Email OTP par lagta hai).
 - Kharcha bachana ho to Google/Email login ko pehle rakhein, mobile OTP ko optional.
 - Abhi sirf India (+91) numbers allowed hain.
 - Reminder sirf email se jate hain (Firebase se custom SMS nahi bhej sakte), isliye profile mein email jodna zaroori batayein.

STEP 3: Deploy
 cd functions && npm install && cd ..
 firebase deploy
 Deploy ke baad link milega: https://<project-id>.web.app

STEP 4: Pehle DEMO_MODE mein test
 functions/.env mein DEMO_MODE=true hai: Email OTP bheja nahi jata, Firebase Console > Functions > Logs mein dikhta hai (mobile OTP ke liye test numbers use karein),
 aur UPI sirf format se verify hoti hai.
 2-3 account banakar poora flow test karein (register, profile, UPI, group, member add, kist, draw, payout, history).

STEP 5: LIVE karne se pehle (zaroori)
 [ ] functions/.env mein DEMO_MODE=false, phir firebase deploy --only functions
 [ ] Authentication > Settings > Authorized domains mein apna domain jodein
 [ ] App Check (reCAPTCHA) chalu karein taaki koi OTP ka misuse na kare
 [ ] Custom domain (Hosting > Add custom domain)
 [ ] Privacy Policy aur Terms of Use page (DPDP Act 2023 ke hisaab se)
 [ ] Chit Funds Act, 1982 ke tahat apne state mein registration / kisi lawyer se salah
 [ ] Asli paise ke liye licensed payment partner. Abhi payout QR se admin khud karta hai;
     automatic payout ke liye RazorpayX / Cashfree Payouts alag se jodna padega.
 [ ] Aadhaar: ye app sirf aakhri 4 ank rakhta hai aur verify nahi karta. Asli verification ke liye DigiLocker / licensed eKYC.
 [ ] Copyright: footer notice laga hai; software ka asli registration copyright.gov.in par karwayein.

Android/iPhone app: npm i, npx cap add android, npx cap sync, Android Studio mein build.
 Dhyan: Google popup aur Phone Auth (reCAPTCHA) webview mein nahi chalte; Capacitor app mein @capacitor-firebase/authentication plugin lagana hoga. Website/PWA par ye seedha chalte hain.

Jaan lena zaroori (known limits)
 - Group mein member ka naam member jodte waqt ka save hota hai; baad mein profile naam badle to purane group mein purana naam dikhega.
 - Login wali verified mobile/email profile mein badli nahi ja sakti. Dusra contact bina OTP verify ke sirf jaankari ke liye hai.
 - Google se aur OTP se banaye alag accounts agar ek hi email ho to Google login mana ho jata hai (email OTP se login karein).
 - Maine ye code yahan chalakar test nahi kiya (internet nahi tha): syntax check hua hai, par pehle DEMO_MODE mein poora test zaroor karein.
