import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;


public class StringTreeNode {
	private static HashMap<String,StringTreeNode> allNodes;
	private HashSet<StringTreeNode> children;
	public final String name;
	private HashSet<String> perms;
	private boolean danger;
	private StringTreeNode(String name) {
		//Constructor using all variables
		this.children=new HashSet<StringTreeNode>();
		this.perms=new HashSet<String>();
		this.name=name;
		danger=false;
	}
	public static int numNodes() {
		return allNodes.size();
	}
	public static boolean hasNode(String name) {
		return allNodes.containsKey(name);
	}
	public static StringTreeNode get(String name) {
		if (allNodes==null) allNodes=new HashMap<String,StringTreeNode>();
		if (allNodes.containsKey(name)) return allNodes.get(name);
		StringTreeNode newNode=new StringTreeNode(name);
		allNodes.put(name,newNode);
		return newNode;
	}
	public void addPerm(String perm) {
		perms.add(perm);
	}
	public void addAllPerms(StringTreeNode s) {
		perms.addAll(s.perms);
	}
	public void addChild(StringTreeNode s) {
		children.add(s);
	}
	public Iterator<StringTreeNode> childItr() {
		return children.iterator();
	}
	public int numChildren() {
		return children.size();
	}
	public void markDanger() {
		//Mark this node as dangerous. In doing so, all its children are marked as dangerous.
		if (danger) return;
		danger=true;
		Iterator<StringTreeNode> x=children.iterator();
		StringTreeNode nextx;
		while(x.hasNext()) {
			//This loop iterates through children. It marks them all as dangerous.
			nextx=x.next();
			nextx.markDanger();
		} //End of iteration through children using x
		
	}
}
