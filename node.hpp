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
// $Id: node.hpp,v 1.7 2007/01/30 09:49:41 wjhengeveld Exp $
#ifndef _NODE_HPP
#define _NODE_HPP

/*
 *  class hierarchy:

Node  ... begin-end
    ReturnNode   ! when last=ret
    OneWayNode   ... successor
       FallThroughNode    ! when succ=label
       JumpNode           ! when last=jump
    TwoWayNode   ... succA, succB
       ConditinalJumpNode ! when last=jcond
       CallNode           ! when last=call
    N_WayNode     ... list! when last=load PC with expression.
*/

//
// Local includes
// 
#include "desquirr.hpp"
#include "instruction.hpp"
class Node/*{{{*/
{
	public:
		enum NodeType
		{
			CALL,								// XXX: not yet implemented
			CONDITIONAL_JUMP,
			FALL_THROUGH,
			JUMP,
			N_WAY,							// XXX: not yet implemented
			RETURN
		};

		Instruction_list& Instructions() { return mInstructions; }
		Addr Address() const { return mAddress; }
		NodeType Type() const { return mType; }

		BoolArray& Definitions() { return mDefinitions; }
		BoolArray& Uses()        { return mUses; }
		BoolArray& LiveIn()      { return mLiveIn; }
		BoolArray& LiveOut()     { return mLiveOut; }

		bool InLiveOut(short int reg)
		{
			return mLiveOut.Get(reg);
		}

		virtual int SuccessorCount() 
		{ 
			// default implementation
			return 0;
		}

		virtual Addr SuccessorAddress(int index)
		{
			// default implementation
			return INVALID_ADDR;
		}

		virtual Node_ptr Successor(int index)
		{
			Node_ptr result;
			msg("ERROR: Node::Successor called\n");
			return result;
		}

		virtual bool ConnectSuccessor(int index, Node_ptr successor)
		{
			// default implementation
			return false;
		}
        friend std::ostream& operator<< (std::ostream& os, Node& n)
        {
            n.print(os);
            printlist(os, n.Instructions());
            return os;
        }
        virtual void print(std::ostream& os)
        {
            os << boost::format("node %08lx-%08lx #insn=%d")
                    % Address()
					% (Instructions().size() ? Instructions().back()->Address() : 0)
                    % Instructions().size();
            os << " use=" << Uses();
            os << " def=" << Definitions();
            os << " in=" << LiveIn();
            os << " out=" << LiveOut();
        }
		static void CreateList(Instruction_list& instructions,
				Node_list& nodes);
		static void ConnectSuccessors(Node_list& nodes);

		static void FindDefintionUseChains(Node_list& nodes);
		static void LiveRegisterAnalysis(Node_list& nodes);

	protected:
		Node(NodeType type, 
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: mAddress(INVALID_ADDR), mType(type)
		{
			for(Instruction_list::iterator item = begin;
					item != end; 
					item++)
			{
				mInstructions.push_back(*item);
			}

			if (mInstructions.size())
			{
				mAddress = (**mInstructions.begin()).Address();
			}
			else
			{
				message("Warning! Empty node of type %i created!\n", mType);
			}
		}

    public:
        virtual ~Node() {}

	private:
		Addr mAddress;
		NodeType mType;
		Instruction_list mInstructions;

		BoolArray mUses;
		BoolArray mDefinitions;
		BoolArray mLiveIn;
		BoolArray mLiveOut;
};/*}}}*/

class OneWayNode : public Node/*{{{*/
{
	protected:
		OneWayNode(NodeType type, Addr successor,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: Node(type, begin, end), mSuccessorAddress(successor)
		{}

		virtual int SuccessorCount() 
		{ 
			return 1;
		}

		virtual Addr SuccessorAddress(int index)
		{
			return 0 == index ? mSuccessorAddress : INVALID_ADDR;
		}

		virtual Node_ptr Successor(int index)
		{
			Node_ptr result;
			if (0 == index)
				result = mSuccessor;
			else
				msg("ERROR: OneWayNode::Successor(%d) called\n", index);
			return result;
		}

		virtual bool ConnectSuccessor(int index, Node_ptr successor)
		{
			if (0 == index && successor->Address() == mSuccessorAddress)
			{
				mSuccessor = successor;
				return true;
			}
			else
				return false;
		}


	private:
		Addr mSuccessorAddress;
		Node_ptr mSuccessor;
};/*}}}*/

class TwoWayNode : public Node/*{{{*/
{
	protected:
		TwoWayNode(NodeType type, Addr successorA, Addr successorB,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: Node(type, begin, end)
		{
			mSuccessorAddress[0] = successorA;
			mSuccessorAddress[1] = successorB;
		}
		virtual int SuccessorCount() 
		{ 
			return 2;
		}

		virtual Addr SuccessorAddress(int index)
		{
			switch (index)
			{
				case 0:
				case 1:
					return mSuccessorAddress[index];
				default:
					return INVALID_ADDR;
			}
		}

		virtual Node_ptr Successor(int index)
		{
			Node_ptr result;
			switch (index)
			{
				case 0:
				case 1:
					result = mSuccessor[index];
                    break;
				default:
					msg("ERROR: TwoWayNode::Successor(%d) called\n", index);
			}
			return result;
		}

		virtual bool ConnectSuccessor(int index, Node_ptr successor)
		{
			switch (index)
			{
				case 0:
				case 1:
					if (successor->Address() == mSuccessorAddress[index])
					{
						mSuccessor[index] = successor;
						return true;
					}
					// fall through
					
				default:
					return false;
			}
		}


	private:
		Addr mSuccessorAddress[2];
		Node_ptr mSuccessor[2];
};/*}}}*/
#if 0
class N_WayNode : public Node/*{{{*/
{
	protected:
		N_WayNode(const std::vector<Addr> &successor_list, 
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: Node(N_WAY, begin, end)
		{
			mSuccessorAddress = successor_list;
			mSuccessor.resize(successor_list.size());
		}

		virtual int SuccessorCount() 
		{ 
			return mSuccessorAddress.size();
		}

		virtual Addr SuccessorAddress(int index)
		{
            if (index<0 || index>=mSuccessorAddress.size())
                return INVALID_ADDR;
            return mSuccessorAddress[index];
		}

		virtual Node_ptr Successor(int index)
		{
			Node_ptr result;
            if (index<0 || index>=mSuccessor.size()) {
                msg("ERROR: N_WayNode::Successor(%d) called\n", index);
                return result;
            }

            return mSuccessor[index];
		}

		virtual bool ConnectSuccessor(int index, Node_ptr successor)
		{
            if (index<0 || index>=mSuccessorAddress.size())
                return false;

            if (successor->Address() == mSuccessorAddress[index])
            {
                mSuccessor[index] = successor;
                return true;
            }
		}


	private:
        std::vector<Addr> mSuccessorAddress;
        std::vector<Node_ptr> mSuccessor;
};/*}}}*/
#endif
class JumpNode : public OneWayNode/*{{{*/
{
	public:
		JumpNode(Addr destination,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: OneWayNode(JUMP, destination, begin, end)
		{}
        virtual void print(std::ostream& os)
        {
            Node::print(os);
            os << boost::format("JUMP target=%08lx\n")
                    % SuccessorAddress(0);
        }

		static Node_ptr CreateFrom(Instruction_ptr i,
				Instruction_list::iterator begin,
				Instruction_list::iterator end);
};/*}}}*/

class ConditionalJumpNode : public TwoWayNode /*{{{*/
{
	public:
		ConditionalJumpNode(
				Addr destination, Addr follower,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: TwoWayNode(CONDITIONAL_JUMP, destination, follower, begin, end)
		{}
        virtual void print(std::ostream& os)
        {
            Node::print(os);
            os << boost::format("CONDJUMP target=%08lx follow=%08lx\n")
                    % SuccessorAddress(0)
                    % SuccessorAddress(1);
        }


		static Node_ptr CreateFrom(Instruction_ptr i,
				Addr follower,
				Instruction_list::iterator begin,
				Instruction_list::iterator end);
};/*}}}*/

class FallThroughNode : public OneWayNode/*{{{*/
{
	public:
		FallThroughNode(
				Addr follower,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: OneWayNode(FALL_THROUGH, follower, begin, end)
		{}
        virtual void print(std::ostream& os)
        {
            Node::print(os);
            os << boost::format("FALLTHROUGH follow=%08lx\n")
                    % SuccessorAddress(0);
        }


};/*}}}*/

class ReturnNode : public Node/*{{{*/
{
	public:
		ReturnNode(
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: Node(RETURN, begin, end)
		{}

        virtual void print(std::ostream& os)
        {
            Node::print(os);
            os << boost::format("RETURN\n");
        }
};/*}}}*/

class CallNode : public TwoWayNode
{
	public:
		CallNode(
				Addr calladdr,
				Addr follower,
				Instruction_list::iterator begin,
				Instruction_list::iterator end)
			: TwoWayNode(CALL, calladdr, follower, begin, end)
		{}
        virtual void print(std::ostream& os)
        {
            Node::print(os);
            os << boost::format("CALL target=%08lx follow=%08lx\n")
                % SuccessorAddress(0)
                % SuccessorAddress(1);
        }
};

#endif

