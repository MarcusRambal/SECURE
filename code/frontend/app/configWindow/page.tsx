
import styles from "./page.module.css"
import { ConfigPanel } from "../../components/dashboard/ConfigPanel";

export default function configurationWindow() {

    return (
        <div className= {styles.configurationWindowContainer}>
                
            <ConfigPanel/>

        </div>
    )
}