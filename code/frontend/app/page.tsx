// app/page.tsx

'use client'

//Components 
import styles from "./page.module.css";


export default function Home() {

  const handleNav = () => {
      window.open('/configWindow')
  };


  return (
    <div className= {styles.mainWindowContainer}>

            <button className = {styles.mainButton}  onClick={handleNav}>Start</button>
    </div>
  );
}
