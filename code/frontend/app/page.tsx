// app/page.tsx

//Components 
import styles from "./page.module.css";
import { TargetInput } from "../components/dashboard/TargetInput";
import { ConfigPanel } from "../components/dashboard/ConfigPanel";
import { ReportPanel } from "../components/dashboard/ReportPanel";
import { TracePanel } from "../components/dashboard/TracePanel";


export default function Home() {
  return (
    <div className= {styles.mainWindowContainer}>

        <div className = {styles.inputConfigContainer}>

            <div className = {styles.targetInputContainer} >
                <TargetInput />
              </div> {/* Target Input */}

            <div className = {styles.configPanelContainer} >
                <ConfigPanel />
            </div>  {/* Config Panel */}
          
          </div> {/* Input Config Container lado izquierdo */}


        <div className = {styles.metricsContainer}>

          <div className  = {styles.reportContainer}>
              <ReportPanel />
            </div> {/* Report Container */}

           <div className = {styles.traceContainer}>
                <TracePanel />
            </div>{/* Trace Container */}

        </div> {/* Metrics Container lado derecho */}
    </div>
  );
}
