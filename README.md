# AndroidAdAnalysis
Soot transformer for analyzing what percentage of calls from dangerous permissions come from ad libraries.

To use this transformer, add it to Soot. The following is an example of how to do so when running Soot through Eclipse:


        AdAnalysisTransformer aat=new AdAnalysisTransformer();
        aat.name="AppNameHere"; 
        PackManager.v().getPack("wjtp").add(new Transform("wjtp.aat", aat));
        
It is recommended to set the name variable to the name of the app to be analyzed, but this is not strictly necessary.

This transformer generates a results file called "Results_for_%name%.txt". This file contains statistics including the number of calls
to dangerous permissions from ad libraries and the number of calls to such permissions from the app itself. The file also lists in
more detail which methods call each permission.

StringTreeNode is a helper class containing a simple Tree Node implementation.
