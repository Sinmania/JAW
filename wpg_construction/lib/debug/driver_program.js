/*
	Copyright (C) 2020  Soheil Khodayari, CISPA
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.


	Description:
	------------
	A test file for debugging purposes only
*/


var jsParser = require('../main/jsparser');
var esgraph = require('../esgraph/index'),
	factoryFlowNode = require('../esgraph/flownodefactory'),
	FlowNode = require('../esgraph/flownode'),
	sourceReader = require('../main/sourcereader');


/**
 * Get the CFG of the AST with additional information
 * @param {Object} ast JS parsed AST
 * @returns {Object} An 3-entries array representing CFG, [start, end, all nodes]
 */
var getCFG = function (ast) {
	'use strict';
	var cfg = esgraph(ast),
		maxLine = 0,
		maxCol = 0;
	for(var index = 0; index < cfg[2].length; ++index) {
		/// specify line number and column offset for nodes beside the entry and exit nodes
		if (cfg[2][index].type !== FlowNode.EXIT_NODE_TYPE) {
			(cfg[2][index]).line = cfg[2][index].astNode.loc.start.line;
			(cfg[2][index]).col = cfg[2][index].astNode.loc.start.column;
			maxLine = (cfg[2][index].line > maxLine)? cfg[2][index].line : maxLine;
			maxCol = (cfg[2][index].col > maxCol)? cfg[2][index].col : maxCol;
		}
	}
	/// specify the value of line number and column offset for the exit node
	cfg[1].line = maxLine;
	cfg[1].col = maxCol + 1;
	return cfg;
};


var filename = './test_program.js';
var code = sourceReader.getSourceFromFile(filename);
var ast = jsParser.parseAST(code, {range: true, loc: true, tolerant: false});
var cfgNodes = getCFG(ast)[2];
jsParser.traverseAST(ast, function(node){
    if(node && node.type){
        let _id = factoryFlowNode.count;
        if(factoryFlowNode.generatedExits.some(e => e.id == _id)){
             factoryFlowNode.count= factoryFlowNode.count + 1; 
             _id = factoryFlowNode.count    
        }
        node._id = _id;
        factoryFlowNode.count= factoryFlowNode.count + 1;           
    }
});


