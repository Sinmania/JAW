#!/usr/bin/env python
#############################################################################
# Functions to find the IDs to some basic sinks for a DOM-based XSS
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
# get all Sinks in one list
#
###
def getAllSinks():
    sinks = []
    sinks.extend(getSink_innerHTML())




###
# Sink #1 some content gets written to the dom, only takes single variables on the right side into consideration
# e.g. document.innerHTML = x
###
def getSink_innerHTML():
    # returns list of IDs
    returnList = []
    neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING,
                                      auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
    with neo_driver.session() as session:
        with session.begin_transaction() as tx:
            query = """
                match (ms{Type:"ExpressionStatement"})-[:AST_parentOf]->(ae{Type:"AssignmentExpression"})-[:AST_parentOf*1..]->(i{Type:"Identifier", Code:"innerHTML"})
                match (ae)-[conn:AST_parentOf{RelationType:"right"}]->(var{Type:"Identifier"})
                return var.Code, ms.Id;
                """
            results = tx.run(query)
            for record in results:
                returnList.append((record['var.Code'], record['ms.Id']))
    return returnList
