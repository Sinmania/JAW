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
import sources as so
import sinks as si
import data_flow as df

sources = []
sinks =[]

def  getAllSources():
    sources.extend(so.getAllSources())

def getAllSinks():
    sinks.extend(si.getAllSinks())

def runShortQueries(tx):
    #Query 1 direct assignment of location
    query = """
    match (n {Type: 'MemberExpression'}), (m{Type: 'Identifier'}), (o{Type:'Identifier', Code:'location'})
    match (o) <-[:AST_parentOf]-(n)-[:AST_parentOf]->(m)
    where m.Code = 'window' OR m.Code = 'document'
    match (si {Type: 'Identifier', Code: 'innerHTML'})
    match (conn {Type: 'AssignmentExpression'})
    match (si)<-[:AST_parentOf*1..30]-(conn)-[:AST_parentOf*1..30]->(n)
    return conn.Location;
    """
    results = tx.run(query)
    for record in results:
        print("vulnerable direct assignment in: " + str(record('conn.Location')))

    #Query 2 direct assignment of an AJAX request
    query = """
    match(aj{Type:'Identifier', Code:'Ajax'})
    match(inner{Type:'Identifier', Code:'innerHTML'})
    match(conn{Type:'ExpressionStatement'})
    match (inner)<-[:AST_parentOf*1..30]-(conn)-[:AST_parentOf*1..30]->(aj)
    return inner, conn.Location, aj;
    """
    results = tx.run(query)
    for record in results:
        print("vulnerable ajax request with direct assignment\n" + str(record['conn.Location']))

    #Query 3 direct assignment of an localStorage value
    query = """
    Match (m{Type:'MemberExpression'}), (ls{Type:'Identifier', Code:'localStorage'})
    Match (m)-[:AST_parentOf {RelationType:'object'}]->(ls)
    match (conn{Type:'MemberExpression'})
    match (inner{Type:'Identifier', Code:'innerHTML'})
    match (inner)<-[:AST_parentOf*1..30]-(conn)-[:AST_parentOf*1..30]->(m)
    return conn;
    """
    results = tx.run(query)
    for record in results:
        print("Vulnerable localStorage access with direct assignment\n" + str(record['conn.Location']))

    #Query 4 direct assignment of an referrer
    query = """
    match (m{Type:'MemberExpression'}), (d{Type:'Identifier', Code:'document'}), (r{Type:'Identifier', Code:'referrer'})
    match (r)<-[:AST_parentOf]-(m)-[:AST_parentOf]->(d)
    match (conn{Type:'MemberExpression'})
    match (inner{Type:'Identifier', Code:'innerHTML'})
    match (inner)<-[:AST_parentOf*1..30]-(conn)-[:AST_parentOf*1..30]->(m)
    return conn;
    """
    results = tx.run(query)
    for record in results:
        print("Vulnerable referrer access with direct assignment\n" + str(record['conn.Location']))

    #Query 5 direct assignment of a cookie
    query = """
    match (m{Type:'MemberExpression'}), (d{Type:'Identifier', Code:'document'}), (r{Type:'Identifier', Code:'cookie'})
    match (r)<-[:AST_parentOf]-(m)-[:AST_parentOf]->(d)
    match (conn{Type:'MemberExpression'})
    match (inner{Type:'Identifier', Code:'innerHTML'})
    match (inner)<-[:AST_parentOf*1..30]-(conn)-[:AST_parentOf*1..30]->(m)
    return conn;
    """
    results = tx.run(query)
    for record in results:
        print("Vulnerable cookie access with direct assignment:\n" + str(record['conn.Location']))


def find_conn():
    for sink in sinks:
        res = df.get_varname_value_from_context(sink[0],sink[1])
        print(res)



getAllSinks()
getAllSources()


neo_driver = GraphDatabase.driver(constantsModule.NEO4J_CONN_STRING, auth=(constantsModule.NEO4J_USER, constantsModule.NEO4J_PASS))
with neo_driver.session() as session:
    with session.begin_transaction() as tx:
        print("starting short queries (direct assignment)")
        runShortQueries(tx)
        find_conn()