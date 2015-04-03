# -*- coding: utf-8 -*-

#
#     Gexf library in python
#     see gephi.org and gexf.net
#
#     repository : http://github.com/paulgirard/pygexf
#     documentation : http://packages.python.org/pygexf
#
#     main developper : Paul Girard, médialab Sciences Po
#     licence : GPL v3
#

from lxml  import etree
from datetime import  date
import itertools
import traceback
 
 
 # missing features : 
 # data validation regarding attribute types
 # phylogeny 
 
 
 # evolution ideas :
 # add display stats on graph composition when exportingto xml
 # add anti-paralell edges test
 
def msg_unexpected_tag(expected, got) :
        print "Error : incorrect xml. Expected tag {expected}, not {got}.".format(expected=expected, got=got)

def ns_clean(token) :
        i = token.find('}')
        return token[i+1:]
        
class Gexf :

    def __init__(self,creator,description):
        self.creator=creator
        self.description=description
        self.graphs=[]
        self.xmlns="http://www.gephi.org/gexf/1.2draft"
        self.xsi="http://www.w3.org/2001/XMLSchema-instance"
        self.schemaLocation="http://www.gephi.org/gexf/1.1draft http://gephi.org/gexf/1.2draft.xsd"
        self.viz="http://www.gexf.net/1.2draft/viz"
        self.version="1.2"
    
    def addGraph(self,type,mode,label,timeformat=""):
        g = Graph(type,mode,label,timeformat)
        self.graphs.append(g)
        return g
     
    def getXML(self):
        gexfXML = etree.Element("{"+self.xmlns+"}gexf",version=self.version,nsmap={None:self.xmlns,'viz':self.viz,'xsi':self.xsi})
#         gexfXML.set("xmlnsxsi",)
        gexfXML.set("{xsi}schemaLocation",self.schemaLocation)
        meta = etree.SubElement(gexfXML, "meta")
        meta.set("lastmodified",date.today().isoformat())
        etree.SubElement(meta, "creator").text=self.creator        
        etree.SubElement(meta, "description").text=self.description
        for graph in self.graphs :
            gexfXML.append(graph.getXML())
            
        return gexfXML
         
    def write(self,file, print_stat=True):
        file.write(etree.tostring(self.getXML(),pretty_print=True,encoding='utf-8',xml_declaration=True))
        if print_stat == True:
            self.print_stat()
     
    def print_stat(self) :
        for graph in self.graphs :
            graph.print_stat()
    
    @staticmethod
    def importXML(gexf_file) :
        """ import gexf xml meta tags to create a Gexf Object and delegate Graph extraction to Graph class"""
        # parse the gexf file
        parser = etree.XMLParser(ns_clean=True)
        tree = etree.parse((gexf_file), parser)
        # start create Gexf Object
        gexf_xml = tree.getroot()
        tag = ns_clean(gexf_xml.tag).lower()
        if tag <> "gexf" :
            msg_unexpected_tag("gexf", tag)
            return
        gexf_obj = None
        for child in gexf_xml :
            tag = ns_clean(child.tag).lower()
            # create a gexf object by importing meta tag
            if tag == "meta" :
                meta_xml = child
                for child in meta_xml :
                    tag = ns_clean(child.tag).lower()
                    if tag  == "creator" :
                        creator = child.text
                    if tag  == "description" :
                        description = child.text
                gexf_obj=Gexf(creator=creator, description=description)
            # export graph xml through Graph Class
            if tag == "graph" :
                graph_xml = child
                if gexf_obj == None :
                    msg_unexpected_tag("meta", tag)
                    return
                Graph.importXML(graph_xml,gexf_obj)
        return gexf_obj
 
class Graph :
    
    def __init__(self,type,mode,label,time_format="double",start="",end="") :
        
        # control variable
        self.authorizedType=("directed","undirected")
        self.authorizedMode=("dynamic","static")
        # time format
        # Discrete: integer or double
        # Continuous : date (yyyy-mm-dd) or dateTime 
        # default : double
        self.authorizedTimeFormat=("integer","double","date","dateTime")
        
        self.defaultTimeFormat="double"
        self.defaultType="directed"
        self.defaultMode="static"
        
        self.label=label
        
        if type in self.authorizedType :
            self.type=type
        else :
            self.type=self.defaultType
        if mode in self.authorizedMode :
            self.mode=mode
        else :
            self.mode=self.defaultMode
        
        if time_format in self.authorizedTimeFormat :
            self.time_format=time_format
        else :
            self.time_format=self.defaultTimeFormat
    
        self.start=start
        self.end = end
        
        
        self._attributes=  Attributes()
        self.attributes =  self._attributes
        self._nodes={}
        self.nodes=self._nodes
        self._edges={}
        self.edges=self._edges
        
    def addNode(self,id,label,start="",end="",startopen=False,endopen=False,pid="",r="",g="",b="",spells=[]) :
        self._nodes[str(id)]=Node(self,id,label,start,end,pid,r,g,b,spells,startopen,endopen)
        return self._nodes[str(id)]
    
    def nodeExists(self,id) :
        if id in self._nodes.keys():
            return 1
        else :
            return 0
        
    def addEdge(self,id,source,target,weight="",start="",end="",label="",r="",g="",b="",spells=[],startopen=False,endopen=False) :
        self._edges[str(id)]=Edge(self,id,source,target,weight,start,end,label,r,g,b,spells,startopen,endopen)
        return self._edges[str(id)]
    
    def addNodeAttribute(self,title,defaultValue=None,type="integer",mode="static", force_id="") :
        # add to NodeAttributes
        return self._attributes.declareAttribute("node",type,defaultValue,title,mode,force_id)

    def addDefaultAttributesToNode(self,node) :
        """ deprecated """
        pass
            
    def checkNodeAttribute(self,id,value,start,end):
        """deprecated"""
        pass
        # check conformity with type is missing
       #  if id in self._nodesAttributes.keys() :
#             if self._nodesAttributes[id]["mode"]=="static" and ( not start=="" or not end=="") : 
#                 raise Exception("attribute "+str(id)+" is static you can't specify start or end dates. Declare Attribute as dynamic")
#             return 1        
#         else :
#             raise Exception("attribute id unknown. Add Attribute to graph first")

        
    def addEdgeAttribute(self,title,defaultValue,type="integer",mode="static", force_id=""):
        return self._attributes.declareAttribute("edge",type,defaultValue,title,mode,force_id)
            
            
    def addDefaultAttributesToEdge(self,edge) :
        """ deprecated """
        pass
            
    def checkEdgeAttribute(self,id,value,start,end):
        """deprecated """
        pass
#         # check conformity with type is missing
#         if id in self._edgesAttributes.keys() :
#             if self._edgesAttributes[id]["mode"]=="static" and ( not start=="" or not end=="") : 
#                 raise Exception("attribute "+str(id)+" is static you can't specify start or end dates. Declare Attribute as dynamic")
#             return 1        
#         else :
#             raise Exception("attribute id unknown. Add Attribute to graph first")

    
    def getXML(self) :
        # return lxml etree element
        graphXML = etree.Element("graph",defaultedgetype=self.type,mode=self.mode,label=self.label,timeformat=self.time_format)
        
        for attributesElement in self.attributes.getAttributesDeclarationXML() :
            graphXML.append(attributesElement)
        
        nodesXML = etree.SubElement(graphXML, "nodes")
        node_ids=self._nodes.keys()
        node_ids.sort()
        for id in node_ids :
            nodesXML.append(self._nodes[id].getXML())
            
        edgesXML = etree.SubElement(graphXML, "edges")
        edge_ids=self._edges.keys()
        edge_ids.sort()
        for id in edge_ids :
            edgesXML.append(self._edges[id].getXML())
            
        return graphXML
    
    @staticmethod
    def importXML(graph_xml,gexf_obj) :
        """ import graph xml tag to create a Graph Object and delegate Node/Edges extraction to Edge/Node class"""
        # get Graph attributes
        type = ""
        mode = ""
        label = ""
        timeformat="double"
        for attr in graph_xml.attrib :
            attr = attr.lower()
            if attr == "defaultedgetype" :
                type = graph_xml.attrib[attr]
            if attr == "mode" :
                mode = graph_xml.attrib[attr]
            if attr == "label" :
                label = graph_xml.attrib[attr]
            if attr == "timeformat" :
                timeformat = graph_xml.attrib[attr]
        # create and attache the graph object to the Gexf object
        graph_obj = gexf_obj.addGraph(type=type, mode=mode, label=label,timeformat=timeformat)
        
        for child in graph_xml :
            tag = ns_clean(child.tag).lower()
            
            if tag == "attributes" :
                attributes_xml = child
                # Delegate Attributes declaration to the attribute object
                graph_obj.attributes.importAttributesXML(attributes_xml)
                
            if tag == "nodes" :
                nodes_xml = child
                # Delegate nodes creation to the Node class
                Node.importXML(nodes_xml,graph_obj)
            if tag == "edges" :
                edges_xml = child
                # Delegate edges creation to the Edge class
                Edge.importXML(edges_xml,graph_obj)
        
    def print_stat(self):
        print self.label+" "+self.type+" "+self.mode+" "+self.start+" "+self.end
        print "number of nodes : "+str(len(self._nodes))
        print "number of edges : "+str(len(self._edges))

class Attributes(dict):
    """ 
        attributes=
        {
         "node" :
            { "id1" : {"id":"id1","title":"age","type":"integer","defaultValue":50,"mode":"static"}, },
         "edge" :
            { "id2" : {"id":"id2","title":"relationship","type":"string","defaultValue":"friend",mode:"dynamic"}, },
        }            
            
            
    """
    def __init__(self):
        self.type_choices=["integer","string","float","double","boolean","date","URI"]
        self.attClass_choices=["node","edge"]
        self.mode_choices=["static","dynamic"]
        for attClass in self.attClass_choices :
            self[attClass]={}
    
    def declareAttribute(self,attClass,type,defaultValue,title="",mode="static",id=None) :
        """
            add a new attribute declaration to the graph
        """
        if attClass in self.attClass_choices :
            # should add quality control here on type and defaultValue
            # if no id given generating a numerical one based on dict length
            if not id : 
                id = str(len(self[attClass]))
            self[attClass][id]={"id":id,"type":type,"defaultValue":defaultValue,"mode":mode,"title":title}
            return id
        else :
            raise Exception("wrong attClass : "+str(attClass)+" Should be in "+str(type_choices))
            
            
    def makeAttributeInstance(self,attClass,id=None,value=None,start=None,end=None,startopen=False,endopen=False) :
        """
           generate an attribute to be include to a node or edge.
           copied from the declared attributes, thus any attribute has to be declared first 
        """
        if attClass in self.attClass_choices :
            if id in self[attClass].keys() :
                att={"id":id}
                att["value"]=value if value else self[attClass][id]["defaultValue"]
                if self[attClass][id]["mode"]=="dynamic" and start or end :
                # start & end will be discarded if the mode is set to static
                    if start :
                        att["start"]=start
                    if startopen :
                        att["startopen"]=startopen
                    if end : 
                        att["end"]=end 
                    if endopen :
                        att["endopen"]=endopen
                return att
            else :
                raise Exception("wrong attribute id (%s), declare the attribute first with declareAttribute"%(id,))
        else :
            raise Exception("wrong attClass : "+str(attClass)+" Should be in "+str(self.type_choices))
    
    def getAttributesDeclarationXML(self) :
        """ generate attributes declaration XML """
        # return lxml etree element
        allAttributesXML=[]
        if len(self)>0 :
            # iter on node and then edge atts
            for attClass,atts in self.iteritems() :
                # group by mode
                key_mode=lambda att : att["mode"]
                atts_sorted_by_mode=sorted(atts.values(),key=key_mode,reverse=True)
                for mode,atts in itertools.groupby(atts_sorted_by_mode,key_mode)  :
                    # generate on attributes by mode
                    attributesXML = etree.Element("attributes")
                    attributesXML.set("class",attClass)
                    attributesXML.set("mode",mode)
                    # generate attribute by id order
                    for att in sorted(atts,key=lambda att: att["id"]) :
                        attributeXML=etree.SubElement(attributesXML, "attribute")
                        attributeXML.set("id",str(att["id"]))
                        attributeXML.set("title",att["title"])
                        attributeXML.set("type",att["type"])
                        if att["defaultValue"] :
                            etree.SubElement(attributeXML, "default").text=att["defaultValue"]
                    allAttributesXML.append(attributesXML)    
        return allAttributesXML
        
    @staticmethod     
    def getAttributesXML(atts) :
        """ get XML attValues for an element (Node or Edge) by passing an attribute values list (stored in Nodes and Edges)"""
        if len(atts)>0:
            attValuesXML = etree.Element("attvalues")
            for att in atts :
                attValueXML=etree.SubElement(attValuesXML, "attvalue")
                attValueXML.set("for",str(att["id"]))
                attValueXML.set("value",att["value"])
                if "start" in att.keys() and not att["start"]=="" :
                    attValueXML.set("start" if not "startopen" in att.keys() or not att["startopen"] else "startopen",att["start"])
                if "end" in att.keys() and not att["end"]=="" :
                    attValueXML.set("end" if not "endopen" in att.keys() or not att["endopen"] else "endopen",att["end"])
            return attValuesXML
        else :
            return None
            
    def importAttributesXML(self,attributes_xml):
        """ get XML attributes declaration of a graph gexf"""
        attr_class = None
        mode = ""
        for attr in attributes_xml.attrib :
            attr = attr.lower()
            if attr == "class" :
                attr_class = attributes_xml.attrib[attr].lower()
            if attr == "mode" :
                mode = attributes_xml.attrib[attr]
        
        for child in attributes_xml :
            tag = ns_clean(child.tag).lower()
            if tag == "attribute" :
                attribute_xml = child
                id = ""
                title = ""
                type = ""
        
                for attr in attribute_xml.attrib :
                    attr = attr.lower()
                    if attr == "id" :
                        id = attribute_xml.attrib[attr]
                    if attr == "title" :
                        title = attribute_xml.attrib[attr]
                    if attr == "type" :
                        type = attribute_xml.attrib[attr]
        
                default = ""
        
                for child in attribute_xml :
                    tag = ns_clean(child.tag).lower()
                    if tag == "default" :
                        default = child.text
        
                self.declareAttribute(attr_class,type,default,title,mode,id)
                
    def importAttributesValuesXML(self,attClass,attvalues_xml):
        """ import attributes values from attvalues gexf xml tag attached to nodes or edges"""
        atts=[]
        for attvalues in attvalues_xml :
            for child in attvalues :
                tag = ns_clean(child.tag).lower()
                if tag == "attvalue" :
                    attvalue_xml = child
                    id = ""
                    value = ""
                    start = ""
                    startopen=False
                    end = ""
                    endopen=False
                    for attr in attvalue_xml.attrib :
                        if attr == "for" :
                            id = attvalue_xml.attrib[attr]
                        if attr == "value" :
                            value = attvalue_xml.attrib[attr]
                        if attr == "start" :
                            start = attvalue_xml.attrib[attr]
                        if attr == "end" :
                            end = attvalue_xml.attrib[attr]
                        if attr == "startopen" :
                            start = attvalue_xml.attrib[attr]
                            startopen = True
                        if attr == "endopen" :
                            end = attvalue_xml.attrib[attr]
                            endopen = True
                          
                    atts.append(self.makeAttributeInstance(attClass,id,value,start,end,startopen,endopen))
        return atts

class Spells(list):
    ''' 
    spells are time periods
    spells is a list of dictionaries
    a spell is a dict : {"start":"YYYY-MM-DD","end":"YYYY-MM-DD"}
    '''
    

    def getXML(self):
        
        spellsXML=etree.Element("spells")
        for spell in self : 
            spellXML=etree.SubElement(spellsXML, "spell")
            if "start" in spell.keys() :
                spellXML.set("start",spell["start"])
            if "end" in spell.keys() :
                spellXML.set("end",spell["end"])
        return spellsXML

    @staticmethod
    def importXML(spellsxmltree):
        return Spells([ spell.attrib for spell in spellsxmltree])
        
           
class Node :

    def __init__(self,graph,id,label,start="",end="",pid="",r="",g="",b="",spells=[],startopen=False,endopen=False) :
        self.id =id 
        self.label=label
        self.start=start
        self.startopen=startopen
        self.end=end
        self.endopen=endopen
        self.pid=pid
        self._graph=graph
        self.setColor(r,g,b)
        
        #spells expecting format = [{start:"",end:""},...]
        self.spells= spells
        
        if not self.pid=="" :
            if not self._graph.nodeExists(self.pid) :
                raise Exception("pid "+self.pid+" node unknown, add nodes to graph first")

        self._attributes=[]
        self.attributes=self._attributes
        
        # add existing nodesattributes default values : bad idea and unecessary
        #self._graph.addDefaultAttributesToNode(self)
        
    def addAttribute(self,id,value,start="",end="",startopen=False,endopen=False) :
        self._attributes.append(self._graph.attributes.makeAttributeInstance("node",id,value,start,end,startopen,endopen))
            
    def getXML(self) :
        # return lxml etree element
        try :
            nodeXML = etree.Element("node",id=str(self.id),label=self.label)
            if not self.start == "":
                nodeXML.set("start" if not self.startopen else "startopen",self.start)
            if not self.end == "":
                nodeXML.set("end" if not self.endopen else "endopen" ,self.end)
            if not self.pid == "":
                nodeXML.set("pid",self.pid)
            
            # attributes
            if self._attributes :
                nodeXML.append(Attributes.getAttributesXML(self._attributes))
            
            # spells
            if self.spells :
                print "found spells in node "+self.id
                nodeXML.append(self.spells.getXML())
                
            
            if not self.r=="" and not self.g=="" and not self.b=="" :
                #color : <viz:color r="239" g="173" b="66"/>
                colorXML = etree.SubElement(nodeXML, "{http://www.gexf.net/1.1draft/viz}color")
                colorXML.set("r",self.r)
                colorXML.set("g",self.g)
                colorXML.set("b",self.b)
            
            return nodeXML
        except Exception, e:
            print self.label
            print self._attributes    
            print e
            traceback.print_exc()
            exit()    
            
    def getAttributes(self):
        attsFull=[]
        for att in self._attributes :
            attFull=self._graph.attributes["node"][att["id"]].copy()
            attFull.update(att)
            attsFull.append(attFull)
        return attsFull
    
    @staticmethod
    def importXML(nodes_xml,graph_obj) :
    
        for child in nodes_xml :
            tag = ns_clean(child.tag).lower()
            if tag == "node" :
                node_xml = child
                id = ""
                label = ""
                start = ""
                startopen=False
                end = ""
                endopen=False
                pid = ""
                r = ""
                g = ""
                b = ""
        
                for attr in node_xml.attrib :
                    attr = attr.lower()
                    if attr == "id" :
                        id = node_xml.attrib[attr]
                    if attr == "label" :
                        label = node_xml.attrib[attr]
                    if attr == "start" :
                        start = node_xml.attrib[attr]
                    if attr == "end" :
                        start = node_xml.attrib[attr]
                    if attr == "startopen" :
                        start = attvalue_xml.attrib[attr]
                        startopen=True
                    if attr == "endopen" :
                        end = attvalue_xml.attrib[attr]
                        endopen=True
                    if attr == "pid" :
                        pid = node_xml.attrib[attr]
        
        
                attvalues_xml = []
                spells=[]
        
                for child in node_xml :
                    tag = ns_clean(child.tag).lower()
                    if tag == "attvalues" :
                        attvalues_xml.append(child)
                    if tag == "viz:color" :
                        r = child.attrib["r"]
                        g = child.attrib["g"]
                        b = child.attrib["b"]
                    if tag =="spells" :
                        spells=Spells.importXML(child)
                        
        
                
                node_obj = graph_obj.addNode(id=id, label=label, start=start, end=end, startopen=startopen, endopen=endopen, pid=pid, r=r, g=g, b=b,spells=spells)
                node_obj._attributes =graph_obj.attributes.importAttributesValuesXML("node",attvalues_xml) 
            

    
    def setColor(self,r,g,b) :
        self.r=r
        self.g=g
        self.b=b
    
    def __str__(self):
        return self.label
    
class Edge :

    def __init__(self,graph,id,source,target,weight="",start="",end="",label="",r="",g="",b="",spells=[],startopen=False,endopen=False) : 

        self.id =id
        self._graph=graph
        
        
        if self._graph.nodeExists(source) :
            self._source=source
            self.source=self._source
        else :
            raise Exception("source "+source+" node unknown, add nodes to graph first")
            
        if self._graph.nodeExists(target) :
            self._target=target
            self.target=self._target
        else:
            raise Exception("target "+target+" node unknown, add nodes to graph first")    
                    
        self.start=start
        self.startopen=startopen
        self.end=end
        self.endopen=endopen

        self.weight=weight
        self.label=label
        self._attributes=[]
        self.attributes=self._attributes
        # COLOR on edges now supported in GEXF 1.2
        self.setColor(r,g,b)
        
        #spells expecting format = [{start:"",end:""},...]
        self.spells= Spells(spells)
        
        # add existing nodesattributes default values : bad idea and unecessary
        #self._graph.addDefaultAttributesToEdge(self)
        
        
    def addAttribute(self,id,value,start="",end="",startopen=False,endopen=False) :
        self._attributes.append(self._graph.attributes.makeAttributeInstance("edge",id,value,start,end,startopen,endopen))
        
    
    def getXML(self) :
        # return lxml etree element
        try :
            edgeXML = etree.Element("edge",id=str(self.id),source=str(self._source),target=str(self._target))
            if not self.start == "":
                edgeXML.set("start" if not self.startopen else "startopen",self.start)
            if not self.end == "":
                edgeXML.set("end" if not self.endopen else "endopen" ,self.end)
            if not self.weight == "":
                edgeXML.set("weight",str(self.weight))
            if not self.label == "":
                edgeXML.set("label",self.label)
            
            # attributes
            if self._attributes :
                edgeXML.append(Attributes.getAttributesXML(self._attributes))
            
            # spells
            if self.spells :
                #spellsXML = etree.SubElement(edgeXML, "spells")
                #spellsXML.append(self.spells.getXML())
                edgeXML.append(self.spells.getXML())

            # COLOR on edges is supported in GEXF since 1.2                
            if not self.r=="" and not self.g=="" and not self.b=="" :
                #color : <viz:color r="239" g="173" b="66"/>
                colorXML = etree.SubElement(edgeXML, "{http://www.gexf.net/1.2draft/viz}color")
                colorXML.set("r",self.r)
                colorXML.set("g",self.g)
                colorXML.set("b",self.b)

                        
                        
            return edgeXML
        except Exception, e:
            print self._source+" "+self._target    
            print e
            exit()    
            
    def getAttributes(self):
        attsFull=[]
        for att in self._attributes :
            attFull=self._graph.attributes["edge"][att["id"]].copy()
            attFull.update(att)
            attsFull.append(attFull)
        return attsFull
            
    @staticmethod
    def importXML(edges_xml,graph_obj) :
        
        for child in edges_xml :
            
            tag = ns_clean(child.tag).lower()
            if tag == "edge" :
                edge_xml = child
                id = ""
                source = ""
                target = ""
                weight = ""
                start = ""
                startopen=False
                end = ""
                endopen=False
                label = ""
                r = ""
                g = ""
                b = ""
                
                for attr in edge_xml.attrib :
                    attr = attr.lower()
                    if attr == "id" :
                        id = edge_xml.attrib[attr]
                    if attr == "source" :
                        source = edge_xml.attrib[attr]
                    if attr == "target" :
                        target = edge_xml.attrib[attr]
                    if attr == "weight" :
                        weight = edge_xml.attrib[attr]
                    if attr == "start" :
                        start = edge_xml.attrib[attr]
                    if attr == "end" :
                        end = edge_xml.attrib[attr]
                    if attr == "startopen" :
                        start = edge_xml.attrib[attr]
                        startopen=True
                    if attr == "endopen" :
                        end = edge_xml.attrib[attr]
                        endopen=True
                    if attr == "label" :
                        label = edge_xml.attrib[attr]
        
                spells=[]
                attvalues_xml=[]
                for child in edge_xml :
                    tag = ns_clean(child.tag).lower()
                    if tag == "attvalues" :
                        attvalues_xml.append(child)
                    if tag =="spells" :
                        spells=Spells.importXML(child)
                    if tag == "viz:color" :
                        r = child.attrib["r"]
                        g = child.attrib["g"]
                        b = child.attrib["b"]
        
                edge_obj = graph_obj.addEdge(id=id, source=source, target=target, weight=weight, start=start, end=end,startopen=startopen,endopen=endopen,label=label,r=r,g=g,b=b, spells=spells)
                edge_obj._attributes=graph_obj.attributes.importAttributesValuesXML("edge",attvalues_xml)

            
            
# COLOR on edges is supported in GEXF since 1.2           
    def setColor(self,r,g,b) :
        self.r=r
        self.g=g
        self.b=b
            

class GexfImport :
# class coded by elie Rotenberg, médialab 20/07/2010
# deprecated : import XML codes are now included to the Gexf, Graph, Attribute, Node, Edge classes

    def __init__(self, file_like) :
        parser = etree.XMLParser(ns_clean=True)
        tree = etree.parse(file_like, parser)
        gexf_xml = tree.getroot()
        tag = self.ns_clean(gexf_xml.tag).lower()
        if tag <> "gexf" :
            self.msg_unexpected_tag("gexf", tag)
            return
        self.gexf_obj = None
        for child in gexf_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "meta" :
                meta_xml = child
                self.gexf_obj = self.extract_gexf_obj(meta_xml)
            if tag == "graph" :
                graph_xml = child
                if self.gexf_obj == None :
                    self.msg_unexpected_tag("meta", tag)
                    return
                self.graph_obj = self.extract_graph_obj(graph_xml)
                

    def ns_clean(self, token) :
        i = token.find('}')
        return token[i+1:]
    
    def msg_unexpected_tag(self, expected, got) :
        print "Error : incorrect xml. Expected tag {expected}, not {got}.".format(expected=expected, got=got)

    def extract_gexf_obj(self, meta_xml) :
        for child in meta_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag  == "creator" :
                creator = child.text
            if tag  == "description" :
                description = child.text
        return Gexf(creator=creator, description=description)

    def extract_graph_obj(self, graph_xml) :
        type = ""
        mode = ""
        label = ""
        timeformat="double"
        for attr in graph_xml.attrib :
            attr = attr.lower()
            if attr == "defaultedgetype" :
                type = graph_xml.attrib[attr]
            if attr == "mode" :
                mode = graph_xml.attrib[attr]
            if attr == "label" :
                label = graph_xml.attrib[attr]
            if attr == "timeformat" :
                timeformat = graph_xml.attrib[attr]

        self.graph_obj = self.gexf_obj.addGraph(type=type, mode=mode, label=label,timeformat=timeformat)

        for child in graph_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attributes" :
                attributes_xml = child
                self.extract_attributes(attributes_xml)
            if tag == "nodes" :
                nodes_xml = child
                self.extract_nodes(nodes_xml)
            if tag == "edges" :
                edges_xml = child
                self.extract_edges(edges_xml)

    def extract_attributes(self, attributes_xml) :
        attr_class = None
        mode = ""
        for attr in attributes_xml.attrib :
            attr = attr.lower()
            if attr == "class" :
                attr_class = attributes_xml.attrib[attr].lower()
            if attr == "mode" :
                mode = attributes_xml.attrib[attr]
        
        for child in attributes_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attribute" :
                attribute_xml = child
                self.extract_attribute(attribute_xml, attr_class, mode)

    def extract_attribute(self, attribute_xml, attr_class, mode) :
        id = ""
        title = ""
        type = ""

        for attr in attribute_xml.attrib :
            attr = attr.lower()
            if attr == "id" :
                id = attribute_xml.attrib[attr]
            if attr == "title" :
                title = attribute_xml.attrib[attr]
            if attr == "type" :
                type = attribute_xml.attrib[attr]

        default = ""

        for child in attribute_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "default" :
                default = child.text


        if attr_class == "node" :
            self.graph_obj.addNodeAttribute(title, default, type, mode, force_id=id)

        if attr_class == "edge" :
            self.graph_obj.addEdgeAttribute(title, default, type, mode, force_id=id)
                
    def extract_nodes(self, nodes_xml) :        
        for child in nodes_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "node" :
                node_xml = child
                self.extract_node(node_xml)

    def extract_node(self, node_xml) :
        id = ""
        label = ""
        start = ""
        startopen=False
        end = ""
        endopen=False
        pid = ""
        r = ""
        g = ""
        b = ""

        for attr in node_xml.attrib :
            attr = attr.lower()
            if attr == "id" :
                id = node_xml.attrib[attr]
            if attr == "label" :
                label = node_xml.attrib[attr]
            if attr == "start" :
                start = node_xml.attrib[attr]
            if attr == "end" :
                start = node_xml.attrib[attr]
            if attr == "startopen" :
                start = attvalue_xml.attrib[attr]
                startopen=True
            if attr == "endopen" :
                end = attvalue_xml.attrib[attr]
                endopen=True
            if attr == "pid" :
                pid = node_xml.attrib[attr]


        attvalues_xmls = []
        spells=[]

        for child in node_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attvalues" :
                attvalues_xmls.append(child)
            if tag == "viz:color" :
                r = child.attrib["r"]
                g = child.attrib["g"]
                b = child.attrib["b"]
            if tag =="spells" :
                spells=[ spell.attrib for spell in child ]


        self.node_obj = self.graph_obj.addNode(id=id, label=label, start=start, end=end, startopen=startopen, endopen=endopen, pid=pid, r=r, g=g, b=b,spells=spells)

        for attvalues_xml in attvalues_xmls :
            self.extract_node_attvalues(attvalues_xml)

    def extract_node_attvalues(self, attvalues_xml) :
        for child in attvalues_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attvalue" :
                attvalue_xml = child
                self.extract_node_attvalue(attvalue_xml)

    def extract_node_attvalue(self, attvalue_xml) :
        id = ""
        value = ""
        start = ""
        startopen=False
        end = ""
        endopen=False
        for attr in attvalue_xml.attrib :
            attr = attr.lower()
            if attr == "for" :
                id = attvalue_xml.attrib[attr]
            if attr == "value" :
                value = attvalue_xml.attrib[attr]
            if attr == "start" :
                start = attvalue_xml.attrib[attr]
            if attr == "end" :
                end = attvalue_xml.attrib[attr]
            if attr == "startopen" :
                start = attvalue_xml.attrib[attr]
                startopen=True
            if attr == "endopen" :
                end = attvalue_xml.attrib[attr]
                endopen=True
        self.node_obj.addAttribute(id=id, value=value, start=start, end=end,startopen=startopen,endopen=endopen)
            
    def extract_edges(self, edges_xml) :
        for child in edges_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "edge" :
                edge_xml = child
                self.extract_edge(edge_xml)

    def extract_edge(self, edge_xml) :
        id = ""
        source = ""
        target = ""
        weight = ""
        start = ""
        startopen=False
        end = ""
        endopen=False
        label = ""
        r = ""
        g = ""
        b = ""
        
        for attr in edge_xml.attrib :
            attr = attr.lower()
            if attr == "id" :
                id = edge_xml.attrib[attr]
            if attr == "source" :
                source = edge_xml.attrib[attr]
            if attr == "target" :
                target = edge_xml.attrib[attr]
            if attr == "weight" :
                weight = edge_xml.attrib[attr]
            if attr == "start" :
                start = edge_xml.attrib[attr]
            if attr == "end" :
                end = edge_xml.attrib[attr]
            if attr == "startopen" :
                start = edge_xml.attrib[attr]
                startopen=True
            if attr == "endopen" :
                end = edge_xml.attrib[attr]
                endopen=True
            if attr == "label" :
                label = edge_xml.attrib[attr]

        spells=[]
        attvalues_xml=[]
        for child in edge_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attvalues" :
                attvalues_xml = child
            if tag =="spells" :
                spells=[ spell.attrib for spell in child]
            if tag == "viz:color" :
                r = child.attrib["r"]
                g = child.attrib["g"]
                b = child.attrib["b"]

        self.edge_obj = self.graph_obj.addEdge(id=id, source=source, target=target, weight=weight, start=start, end=end,startopen=startopen,endopen=endopen,label=label,r=r,g=g,b=b, spells=spells)
        self.extract_edge_attvalues(attvalues_xml)

    def extract_edge_attvalues(self, attvalues_xml) :
        for child in attvalues_xml :
            tag = self.ns_clean(child.tag).lower()
            if tag == "attvalue" :
                attvalue_xml = child
                self.extract_edge_attvalue(attvalue_xml)


#    def addAttribute(self,id,value,start="",end="") :

    def extract_edge_attvalue(self, attvalue_xml) :
        id = ""
        value = ""
        start = ""
        startopen=True
        end = ""
        endopen=True
        for attr in attvalue_xml.attrib :
            if attr == "for" :
                id = attvalue_xml.attrib[attr]
            if attr == "value" :
                value = attvalue_xml.attrib[attr]
            if attr == "start" :
                start = attvalue_xml.attrib[attr]
            if attr == "end" :
                end = attvalue_xml.attrib[attr]
            if attr == "startopen" :
                startopen = attvalue_xml.attrib[attr]
            if attr == "endopen" :
                endopen = attvalue_xml.attrib[attr]

        self.edge_obj.addAttribute(id=id, value=value, start=start, end=end,startopen=startopen,endopen=endopen)

    def gexf(self) :
        return self.gexf_obj
