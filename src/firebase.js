import { initializeApp } from "firebase/app";
import { getFirestore } from "firebase/firestore";
import { getAuth } from "firebase/auth";

const firebaseConfig = {
  apiKey: "AIzaSyB8-lvJ3xVD6dh9OcS13FgrQcJ2qmVd0vY",
  authDomain: "ransomeware-8df2a.firebaseapp.com",
  projectId: "ransomeware-8df2a",
  storageBucket: "ransomeware-8df2a.firebasestorage.app",
  messagingSenderId: "234005972742",
  appId: "1:234005972742:web:3ce5f7a26cebc8efe24087"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);

export { db, auth };
