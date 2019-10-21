package crawler;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;


public class Main {

	
	public  final int SAME_ORIGIN_LIMIT=10;
	public  final int SITE_MAX_LINKS=20;

	
	 LinkedList<String> cache=new LinkedList<String>();
	 LinkedList<String> fallback=new LinkedList<String>();
	 LinkedList<String> blockedOrigin=new LinkedList<String>();

	 Map<String, Integer> OriginCounter=new HashMap<>();
	
	
	public static void main(String[] args) throws IOException {
		delete("counter");
		delete("blocked");
		delete("cache");
		delete("vulnerabilities");
		new Main().start();
	}
	private void start() {

		
		fallback.add("http://google.com");
		
		while(! fallback.isEmpty()) {
			
			

			try {
				connect(fallback.removeLast());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}		
	}
	private  void connect(String next) throws IOException {
		System.out.println(next+" "+fallback.size());
		cache.add(next);
		quickLine("cache", next);
		Document doc=null;
		try {
			doc = Jsoup.connect(next).timeout(10000).get();
		}catch(Exception e) {
			return;
		}
		
		analyze(doc,next);
		Elements links = doc.select("a");
		int ctr=SITE_MAX_LINKS;
		for (Element n : links) {
			String l=n.attr("href");
		    if(isValidLink(l)) {
		    	addLink(l);
		    	
		    	if(ctr--==0) {
		    		return;
		    	}
		    }
		}
		
	}
	public void addLink(String l) {
		String o=getOrigin(l);

		fallback.add(l);
		int old=(OriginCounter.get(o)==null?0:OriginCounter.get(o))+1;
		
		
		OriginCounter.put((o),old);
		
		
		if(old+1==SAME_ORIGIN_LIMIT) {
			blockedOrigin.add(o);
			quickLine("blocked", o);
		}
		
	}
	public  boolean  isValidLink(String n) {
		
		if(!n.startsWith("http")) {
			return false;
		}
		if(cache.contains(n)) {
			return false;
		}

		if(blockedOrigin.contains(getOrigin(n)  )) {
			return false;
		}
		return true;
	}
	public String getOrigin(String link) {
		try {
			String []p= link.split("/");
			
			String[] fp=p[2].split("\\.");

			
			return fp[fp.length-2].split("\\?")[0]+"."+fp[fp.length-1].split("\\?")[0];
			
			
		}catch(Exception e) {return null;}
	}

	
	String quickLineBuffer="";
	public void quickLineb(String line) {
		quickLineBuffer+=line+"\n";
	}
	public void quickLine(String file,String line) {
		// append = true
		try(PrintWriter output = new PrintWriter(new FileWriter(file,true))) 
		{
			output.print(quickLineBuffer);
			output.printf("%s\r\n", line);
		} 
	catch (Exception e) {}finally {		quickLineBuffer="";}
	}

	public static void delete(String s) {
        File file = new File(s);
        try {
        	file.renameTo(new File("."+s+"."+new Date()));
        	file.delete();
        }catch(Exception e) {
        	
        }
	}
	
	public void analyze(Element e, String next) {
		Elements formset=e.select("form");
		
		for(Element x:formset) {
			if(x.hasAttr("action")) {
				boolean none=true;
				
				String a=x.attr("action");
				String method=x.attr("method");
				boolean method_post=method!=null&&method.toLowerCase().equals("post");
				if (method=="")
					method="GET";
				
				String script="<h1>blabla</h1>";
				
				quickLineb("\n\n");
				quickLineb(next);
				quickLineb("method:"+method);
				String link=a.startsWith("http")?a:next+a;
				quickLineb(link);
				String curl="curl ";
				String postFixUrl="";
				
				boolean viable=false;
				for(Element p:x.select("input,textarea,select,output,object")) {
					none=false;
					if(p.attr("type").equals("submit")) {
						continue;
					}
					
					String g=String.format("%-10s%-10s%-30s%-20s", p.tagName(),p.attr("type"),p.attr("name"),p.attr("value"));
					quickLineb(g);
					String name=p.attr("name");

					
					String attr=null;
					if(!name.equals(""))
						name+="=";
						
					
					
					if(p.tagName().toLowerCase().equals("textarea")||p.attr("type").toLowerCase().equals("text")) {
						attr=name+script;
						viable=true;
					}else {
						if(p.hasAttr("value")) {
							attr=name+p.attr("value");
						}
						else {
							attr=name+"1";
						}
						
					}
					
					
					if(method_post) {
						curl+="--data \""+attr+"\" ";
					}else {
						
						if(postFixUrl.equals(""))
							postFixUrl+="?";
						else
							postFixUrl+="&";
						
						postFixUrl+=attr;
					}

				}
				quickLineb("\n"+curl+" \""+link+postFixUrl+"\" 2> /dev/null 1| grep \""+script+"\";echo $?");
				if(viable)
					quickLine("vulnerabilities","");
				else
					quickLineBuffer="";
				
				
			}
		}
		
	}
}
