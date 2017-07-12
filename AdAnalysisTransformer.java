import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import soot.Scene;
import soot.SceneTransformer;
import soot.SootMethod;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;


public class AdAnalysisTransformer extends SceneTransformer {
	public String name;
	private static ArrayList<String> readIn(String filename) throws IOException {
    	ArrayList<String> dest=new ArrayList<String>();
    	BufferedReader br = new BufferedReader(new FileReader(filename));
    	while (br.ready()) {
    		dest.add(br.readLine());
    	}
    	br.close();
		return dest;
    }
	private static String getFullName(SootMethod m) {
		return (m.toString().substring(1,m.toString().indexOf(":"))+'.'+m.getName());
	}
	private static void checkForLibrary(HashSet<SootMethod> methodSet,SootMethod method) {
		if (method.getDeclaringClass().isLibraryClass()) {
			methodSet.remove(method);
		} //End of if block
	}
	private static void removeLibraryClasses(HashSet<SootMethod> allMethods) {
		System.out.println("STARTING SIZE: "+allMethods.size());
		Iterator<SootMethod> x=allMethods.iterator();
		SootMethod nextx;
		SootMethod prevx;
		nextx=x.next();
		while(x.hasNext()) {
			//This loop iterates through allMethods.
			prevx=nextx;
			checkForLibrary(allMethods,prevx);
			nextx=x.next();
		} //End of iteration through allMethods using x
		checkForLibrary(allMethods,nextx);
		System.out.println("ENDING SIZE: "+allMethods.size());

	}
	private static boolean checkAdLib(ArrayList<String> adLibs,String method) {
		Iterator<String> x=adLibs.iterator();
		String nextx;
		while(x.hasNext()) {
			//This loop iterates through adLibs. It checks each to see if it method is of its class.
			nextx=x.next();
			if (method.contains(nextx)) {
				return true;
			}
		} //End of iteration through adLibs using x
		return false;
	}
	private void runAnalysis() throws IOException {
		System.out.println("Analysis begins here");
		ArrayList<String> adLibs=readIn("adLib.txt");
		ArrayList<String> nonOther=readIn("nonOther.txt");
		ArrayList<String> maps =readIn("parsedMap.txt");
		//Maps permissions to the methods that use them
		HashMap<String,ArrayList<String> > permMap=new HashMap<String,ArrayList<String> >();
		HashSet<String> permMethods=new HashSet<String>();
		for (int x=0;x<maps.size();x++) {
			//This loop iterates through maps. It copies the information into permMap and methodList.
			String[] methodAndPerm=maps.get(x).split(" ");
			permMethods.add(methodAndPerm[0]);
			if (permMap.containsKey(methodAndPerm[1])) {
				permMap.get(methodAndPerm[1]).add(methodAndPerm[0]);
			} //End of if block
			else {
				permMap.put(methodAndPerm[1], new ArrayList<String>());
				permMap.get(methodAndPerm[1]).add(methodAndPerm[0]);
			} //End of else block
		} //End of iteration through maps using x
    	CallGraph cg = Scene.v().getCallGraph();
        Iterator<Edge> i=cg.iterator();
        Edge nexti;
        HashSet<SootMethod> allMethods=new HashSet<SootMethod>();
        while(i.hasNext()) {
        	nexti=i.next();
        	allMethods.add(nexti.tgt());
        	allMethods.add(nexti.src());
        }
        //removeLibraryClasses(allMethods);
        String destFile="Results_for_"+name+".txt";
        //String destFile="Results.txt";
        BufferedWriter wr=new BufferedWriter(new FileWriter(destFile));
        int numsts=0;
        HashSet<StringTreeNode> rootPerms=new HashSet<StringTreeNode>();
        HashSet<SootMethod> methodsToSearch=new HashSet<SootMethod>();
        Iterator<String> permItr=permMap.keySet().iterator();
    	String nextPerm;
    	while(permItr.hasNext()) {
    		//This loop iterates through permMap.keySet(). It builds the root set of permissions.
    		nextPerm=permItr.next();
    		StringTreeNode currentNode=StringTreeNode.get(nextPerm);
    		rootPerms.add(currentNode);
    		Iterator<String> y=permMap.get(nextPerm).iterator();
    		String nexty;
    		while(y.hasNext()) {
    			//This loop iterates through permMap.get(nextPerm). It maps all permissions to all calling methods.
    			nexty=y.next();
    			currentNode.addChild(StringTreeNode.get(nexty));
    			StringTreeNode.get(nexty).addPerm(currentNode.name);
    			
    		} //End of iteration through permMap.get(nextPerm) using y
    		
    	} //End of iteration through permMap.keySet() using x

        Iterator<SootMethod> x=allMethods.iterator();
		SootMethod nextx;
        while(x.hasNext()) {
        	//This loop iterates through allMethods. It analyzes each method to see if it calls any dangerous permissions.
        	nextx=x.next();
        	if (nextx.isPhantom()) continue;
        	if (!nextx.hasActiveBody()) continue;
        	for (Iterator uIt = nextx.retrieveActiveBody().getUnits().iterator(); uIt.hasNext();) {
				 
				// a Soot object representing a JIMPLE statement
				Stmt s = (Stmt) uIt.next();
				numsts++;
				// not all statements have calls inside them. if there
				// isn't a call, we just go to the next statement
				if ( ! s.containsInvokeExpr() ) continue;
				InvokeExpr call = (InvokeExpr) s.getInvokeExpr();
				SootMethod callee = call.getMethod();
				if (callee.getName()!=null) {
					String calleeFullName=getFullName(callee);
					if (permMethods.contains(calleeFullName)) {
						StringTreeNode calleeNode=StringTreeNode.get(calleeFullName);
						StringTreeNode callerNode=StringTreeNode.get(getFullName(nextx));
						callerNode.addAllPerms(calleeNode);
						calleeNode.addChild(callerNode);
						methodsToSearch.add(nextx);
					} //End of if block
				}
        	}
        }
        String srcName,tgtName;
        StringTreeNode srcNode,tgtNode;
		Edge nexty;
		HashSet<SootMethod> nextMethodsToSearch;
        while (methodsToSearch.size()>0) {
        	nextMethodsToSearch=new HashSet<SootMethod>();
        	x=methodsToSearch.iterator();
        	while(x.hasNext()) {
        		//This loop iterates through methodsToSearch. It updates the STNode tree based on call heirarchies.
        		nextx=x.next();
        		Iterator<Edge> y=cg.edgesInto(nextx);
    			tgtName=getFullName(nextx);
    			tgtNode=StringTreeNode.get(tgtName);
        		while(y.hasNext()) {
        			//This loop iterates through edges into a given method It updates the tree.
        			nexty=y.next();
        			SootMethod caller=nexty.src();
        			srcName=getFullName(caller);
        			if (!StringTreeNode.hasNode(srcName)) {
        				nextMethodsToSearch.add(caller);
        			}
        			srcNode=StringTreeNode.get(srcName);
        			srcNode.addAllPerms(tgtNode);
        			tgtNode.addChild(srcNode);
        		} //End of iteration through each edge into nextx using y
        		
        	} //End of iteration through methodsToSearch using x
        	methodsToSearch=nextMethodsToSearch;
    	}
        wr.write("\r\nnum cg nodes: "+cg.size());
        wr.write("\r\nnum permission methods: "+permMethods.size());
        wr.write("\r\nnum methods using a permission: "+StringTreeNode.numNodes());
        StringTreeNode nextw;
        int edges=0;
        int dangerousEdges=0;
        int appEdges=0;
        StringBuffer details=new StringBuffer();
        Iterator<StringTreeNode> w=rootPerms.iterator();
        while(w.hasNext()) {
        	//This loop iterates through rootPerms. It iterates through all permissions.
        	//and outputs the information to the file.
        	nextw=w.next();
        	details.append("\r\n\r\n========================================\r\nPERMISSION:\r\n"+nextw.name+
        			"\r\n");
        	Iterator<StringTreeNode> y=nextw.childItr();
        	StringTreeNode nextySTN;
        	while(y.hasNext()) {
        		//This loop iterates through all methods that access a permission.
        		//It checks the callers for each edge.
        		nextySTN=y.next();
        		if (nextySTN.numChildren()==0) {
        			continue;
        		}
        		details.append("\r\n-----------------------------------------\r\nMETHOD:\r\n"+nextySTN.name+"\r\nPossible callers:\r\n");
        		Iterator<StringTreeNode> z=nextySTN.childItr();
        		StringTreeNode nextz;
        		while(z.hasNext()) {
        			//This loop iterates through all callers of a particular method.
        			//It checks to see if any are ad libraries.
        			//It also prints each edge to the file.
        			nextz=z.next();
        			edges++;
                	if (checkAdLib(adLibs,nextz.name)) {
                		dangerousEdges++;
                	}
        			details.append(nextz.name+"\r\n");
        		} //End of iteration through nextySTN.children using z
        	} //End of iteration through nextw.children using y
        } //End of iteration through rootPerms using w
        wr.write("\r\nTotal calls to permissions: "+edges);
        wr.write("\r\nTotal ad library calls to permissions: "+dangerousEdges);
        edges=dangerousEdges=0;
        w=rootPerms.iterator();
        ArrayList<String> dangerPerms=readIn("dangerPerms.txt");
        
        while(w.hasNext()) {
        	//This loop iterates through rootPerms. It marks all dangerous permissions and methods that call them.
        	nextw=w.next();
        	for (int y=0;y<dangerPerms.size();y++) {
        		//This loop iterates through dangerPerms. It checks to see if the current permission is dangerous.
        		if (nextw.name.contains(dangerPerms.get(y))) {
        			nextw.markDanger();
            		StringTreeNode nextz;
        			Iterator<StringTreeNode> z=nextw.childItr();
            		while(z.hasNext()) {
            			//Iterates through all methods accessing a permission.
            			//We must count their children and see if any are ad libraries.
            			nextz=z.next();
            			edges+=nextz.numChildren();
            			Iterator<StringTreeNode> a=nextz.childItr();
                		StringTreeNode nexta;
                		while (a.hasNext()) {
                			//Iterate through all methods calling the permission.
                			//Count up the number of dangerous nodes.
                			nexta=a.next();
                        	if (checkAdLib(adLibs,nexta.name)) {
                        		dangerousEdges++;
                        	}
                        	if (checkAdLib(nonOther,nexta.name)) {
                        		appEdges++;
                        	}
                		}
            			
            		}
            		//A permission should only be marked once.
        			break;
        		}
        	} //End of iteration through dangerPerms using y
        }
        wr.write("\r\nTotal dangerous edges: "+edges);
        wr.write("\r\nTotal dangerous edges from app itself: "+appEdges);
        wr.write("\r\nTotal dangerous edges from ad libraries: "+dangerousEdges);
        wr.write(details.toString());
		wr.flush();
        wr.close();
	}
	@Override
	protected void internalTransform(String arg0, Map<String, String> arg1) {
		try {
			runAnalysis();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
