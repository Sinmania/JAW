#!/usr/bin/env python
#############################################################################
# Functions to find the IDs to some basic sources for a DOM-based XSS
# within a HPG representation of a JS application
#
#
#
#
#############################################################################

__author__ = "Dominik Sautter"

import constants as constantsModule
from neo4j import GraphDatabase

###
# get all Sources together in one List
#
###
def  getAllSources():
    sources = []
    sources.extend(getSource_AJAX())
    sources.extend(getSource_cookie())
    sources.extend(getSource_location())
    sources.extend(getSource_referrer())
    sources.extend(getSource_localStorage())
    return sources


###
# Source #1 location as source with var exists beforehand
# e.g. x = document.location
###
def getSource_location():
    #returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING, auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
            match (n)-[:AST_parentOf*1..]->(l{Type:"Identifier", Code:"location"}) 
            where n.Type == "ExpressionStatement" OR n.Type == "VariableDeclaration"                                                                                                                                       
            return n.Id; 
            """
            results = tx.run(query)
            for record in results:
                returnList.append(record['n.Id'])
    return returnList

###
# Source #2 AJAX request as source with var exists beforehand
# e.g. x = *AJAX*
###
def getSource_AJAX():
    # returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING, auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
                match (so)-[:AST_parentOf*1..50]->(aj{Type:'Identifier', Code:'Ajax'})
                where so.Type == "ExpressionStatement" OR so.Type == "VariableDeclaration"                                                                                                                                       
                return so.Id; 
                """
            results = tx.run(query)
            for record in results:
                returnList.append(record['so.Id'])
    return returnList

###
# Source #3 localStorage as source with existing var
# e.g. x = localStorage
###
def getSource_localStorage():
    # returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING,
                                      auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
                    match (so)-[:AST_parentOf*1..50]->(m{Type:'MemberExpression'})-[:AST_parentOf {RelationType:'object'}]->(ls{Type:'Identifier', Code:'localStorage'})                                                                                                                                       
                    where so.Type == "ExpressionStatement" OR so.Type == "VariableDeclaration"
                    return so.Id; 
                    """
            results = tx.run(query)
            for record in results:
                returnList.append(record['so.Id'])
    return returnList

###
# Source #4 referrer as source with existing var
# e.g. x = document.referrer
###
def getSource_referrer():
    # returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING, auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
                    match (m{Type:'MemberExpression'}), (d{Type:'Identifier', Code:'document'}), (r{Type:'Identifier', Code:'referrer'})
                    match (r)<-[:AST_parentOf]-(m)-[:AST_parentOf]->(d)
                    match (so)-[:AST_parentOf*1..50]->(m)
                    where so.Type == "ExpressionStatement" OR so.Type == "VariableDeclaration"                                                                                                                                       
                    return so.Id; 
                    """
            results = tx.run(query)
            for record in results:
                returnList.append(record['so.Id'])
    return returnList

###
# Source #5 cookie as source with existing var
# e.g. x = document.cookie
###
def getSource_cookie():
    # returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING, auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
                    match (m{Type:'MemberExpression'}), (d{Type:'Identifier', Code:'document'}), (r{Type:'Identifer', Code:'cookie'})
                    match (r)<-[:AST_parentOf]-(m)-[:AST_parentOf]->(d)
                    match (so)-[:AST_parentOf*1..50]->(m) 
                    where so.Type == "ExpressionStatement" OR so.Type == "VariableDeclaration"                                                                                                                                      
                    return so.Id; 
                    """
            results = tx.run(query)
            for record in results:
                returnList.append(record['so.Id'])
    return returnList
