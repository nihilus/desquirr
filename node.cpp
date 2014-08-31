// 
// Copyright (c) 2002 David Eriksson <david@2good.nu>
// 
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// $Id: node.cpp,v 1.4 2005/10/15 23:56:03 wjhengeveld Exp $

#include <stack>

#include "node.hpp"
#include "dataflow.hpp"

// this finds consequetive sequences of instructions.
void Node::CreateList(Instruction_list& instructions, Node_list& nodes)/*{{{*/
{
	Instruction_list::iterator cur = instructions.begin();

	if (instructions.end() == cur)
		return;

	Instruction_list::iterator begin = cur++;

	while (cur != instructions.end())
	{
		Node_ptr node;
		Instruction_ptr instruction = *cur;

//		message("%p\n", instruction->Address());

		switch (instruction->Type())
		{
			case Instruction::CONDITIONAL_JUMP:
				cur++;
				node = ConditionalJumpNode::CreateFrom(instruction, 
						instructions.end() == cur ? INVALID_ADDR : (**cur).Address(),
						begin, cur);
				begin = cur;
				break;

			case Instruction::JUMP:
				cur++;
				node = JumpNode::CreateFrom(instruction, begin, cur);
				begin = cur;
				break;

			case Instruction::LABEL:
			case Instruction::CASE:
				if (begin != cur)
				{
					node.reset( new FallThroughNode(instruction->Address(), begin, cur) );
					begin = cur; 
				}
				cur++;	// yes, increase after node creation, not before 
				break;

			case Instruction::RETURN:
				cur++;
				node.reset( new ReturnNode(begin, cur) );
				begin = cur;
				break;
/*
 * TODO: currently call's are in the instruction list as:
 *     AssignmentInstruction(CallExpression())
			case Instruction::CALL:
                cur++;
                node.reset( new CallNode(instruction->Address(), instruction->.., begin, cur) );
                begin = cur;
                break;
*/
/*
			case Instruction::SWITCH:
                cur++;
                node.reset( new N_WayNode(GetSwitchExpression(), begin, cur) );
                begin = cur;
                break;
*/
			default:
				cur++;
				break;
		}

		if (node.get())
		{
			nodes.push_back(node);
		}
	}

	ConnectSuccessors(nodes);
}/*}}}*/

Node_ptr JumpNode::CreateFrom(Instruction_ptr i,/*{{{*/
		Instruction_list::iterator begin,
		Instruction_list::iterator end)
{
	Jump* jump = static_cast<Jump*>(i.get());
	Expression_ptr destination = jump->Operand();
	Addr address;

	if (destination->IsType(Expression::GLOBAL))
	{
		address = static_cast<GlobalVariable*>(destination.get())->Address();
	}
	else
	{
		message("%p Error! Jump destination is not a GlobalVariable!\n", jump->Address());
		address = INVALID_ADDR;
	}

	Node_ptr result ( new JumpNode(address, begin, end) );
	return result;
}/*}}}*/

Node_ptr ConditionalJumpNode::CreateFrom(Instruction_ptr i,/*{{{*/
		Addr follower,
		Instruction_list::iterator begin,
		Instruction_list::iterator end)
{
	ConditionalJump* jump = static_cast<ConditionalJump*>(i.get());
	Expression_ptr destination = jump->Second();
	Addr address;

	if (destination->IsType(Expression::GLOBAL))
	{
		address = static_cast<GlobalVariable*>(destination.get())->Address();
	}
	else
	{
		message("%p Error! Jump destination is not a GlobalVariable!\n", jump->Address());
		address = INVALID_ADDR;
	}

	return Node_ptr( new ConditionalJumpNode(address, follower, begin, end) );
}/*}}}*/

/* Find DU-chains {{{ */
struct FindDefintionUseChainsHelper
{
	void operator() (Node_ptr node)
	{
		Instruction::FindDefintionUseChains(node->Instructions());
	}
};

void Node::FindDefintionUseChains(Node_list& nodes)
{
	for_each(nodes.begin(), nodes.end(), 
			FindDefintionUseChainsHelper());
}/*}}}*/

/* Connect successors {{{ */

typedef std::map<Addr, Node_ptr> Node_map;



struct ConnectSuccessorsMapBuilder
{
	Node_map& mMap;
	
	ConnectSuccessorsMapBuilder(Node_map& map)
		: mMap(map)
	{}
	
	void operator() (Node_ptr node)
	{
		mMap[node->Address()] = node;
	}
};

struct ConnectSuccessorsHelper
{
	Node_map& mMap;
	
	ConnectSuccessorsHelper(Node_map& map)
		: mMap(map)
	{}

	void operator() (Node_ptr node)
	{
		for (int i = 0; i < node->SuccessorCount(); i++)
		{
			Node_map::iterator item = mMap.find( node->SuccessorAddress(i) );
			if (mMap.end() != item)
			{
				bool success = node->ConnectSuccessor(i, item->second);
				if (!success)
				{
					message("Failed to connect successor\n");
				}
			}
			else
			{
				message("%p Unable to find successor block with address %p\n",
						node->Address(),
						node->SuccessorAddress(i) );
			}
		}
	}
};

void Node::ConnectSuccessors(Node_list& nodes)
{
	Node_map map;
	
	for_each(nodes.begin(), nodes.end(), 
			ConnectSuccessorsMapBuilder(map));
	
	for_each(nodes.begin(), nodes.end(), 
			ConnectSuccessorsHelper(map));
}/*}}}*/

/* Live register analysis {{{ */
void Node::LiveRegisterAnalysis(Node_list& nodes)
{
	bool changed;

	do
	{
//		message(".");
		changed = false;

		for (Node_list::reverse_iterator item = nodes.rbegin();
				item != nodes.rend();
				item++)
		{
			Node_ptr node = *item;
			
			BoolArray prev_live_in = node->mLiveIn;
			BoolArray prev_live_out = node->mLiveOut;
			
			for (int i = 0; i < node->SuccessorCount(); i++)
			{
				if (node->Successor(i).get())
					node->mLiveOut |= node->Successor(i)->mLiveIn;
			}

			node->mLiveIn = node->Uses() | (node->mLiveOut & ~node->Definitions());

			if ((prev_live_in != node->mLiveIn) || (prev_live_out != node->mLiveOut))
				changed = true;
		}
	
	} while (changed);
}/*}}}*/

