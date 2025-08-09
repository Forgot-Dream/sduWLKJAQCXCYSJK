#!/usr/bin/env python3
"""
Merkle树实现模块

基于RFC6962标准实现Merkle树，支持10万叶子节点
包含存在性证明和不存在性证明
"""

import hashlib
import math
from typing import List, Tuple, Optional, Dict
from sm3_algorithms import SM3Basic


class MerkleTreeNode:
    """Merkle树节点"""
    
    def __init__(self, hash_value: str, left=None, right=None, is_leaf: bool = False, data: str = None):
        self.hash = hash_value
        self.left = left
        self.right = right
        self.is_leaf = is_leaf
        self.data = data
        self.level = 0
        self.index = 0


class MerkleTree:
    """基于SM3的Merkle树实现"""
    
    def __init__(self):
        self.sm3 = SM3Basic()
        self.root = None
        self.leaves = []
        self.tree_levels = []
        self.leaf_count = 0
    
    def compute_leaf_hash(self, data: str) -> str:
        """计算叶子节点哈希 (RFC6962: 0x00 + data)"""
        leaf_prefix = b'\x00'
        return self.sm3.hash(leaf_prefix + data.encode('utf-8'))
    
    def compute_internal_hash(self, left_hash: str, right_hash: str) -> str:
        """计算内部节点哈希 (RFC6962: 0x01 + left + right)"""
        internal_prefix = b'\x01'
        left_bytes = bytes.fromhex(left_hash)
        right_bytes = bytes.fromhex(right_hash)
        return self.sm3.hash(internal_prefix + left_bytes + right_bytes)
    
    def build_tree(self, leaf_data: List[str]) -> str:
        """构建Merkle树并返回根哈希"""
        if not leaf_data:
            raise ValueError("叶子数据不能为空")
        
        self.leaf_count = len(leaf_data)
        print(f"构建Merkle树，叶子节点数量: {self.leaf_count}")
        
        # 创建叶子节点
        current_level = []
        for i, data in enumerate(leaf_data):
            leaf_hash = self.compute_leaf_hash(data)
            node = MerkleTreeNode(leaf_hash, is_leaf=True, data=data)
            node.level = 0
            node.index = i
            current_level.append(node)
        
        self.leaves = current_level.copy()
        self.tree_levels = [current_level.copy()]
        level = 0
        
        # 自底向上构建树
        while len(current_level) > 1:
            next_level = []
            level += 1
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # 奇数个节点时，复制最后一个节点
                    right = current_level[i]
                
                # 计算内部节点哈希
                internal_hash = self.compute_internal_hash(left.hash, right.hash)
                node = MerkleTreeNode(internal_hash, left, right)
                node.level = level
                node.index = i // 2
                
                next_level.append(node)
            
            self.tree_levels.append(next_level.copy())
            current_level = next_level
        
        self.root = current_level[0]
        print(f"Merkle树构建完成，树高度: {level + 1}")
        return self.root.hash
    
    def get_inclusion_proof(self, leaf_index: int) -> List[Tuple[str, str]]:
        """生成存在性证明 (hash, direction)"""
        if leaf_index >= self.leaf_count:
            raise ValueError(f"叶子索引 {leaf_index} 超出范围")
        
        proof = []
        current_index = leaf_index
        
        for level in range(len(self.tree_levels) - 1):
            level_nodes = self.tree_levels[level]
            
            if current_index % 2 == 0:
                # 当前节点是左子节点，需要右兄弟节点
                if current_index + 1 < len(level_nodes):
                    sibling_hash = level_nodes[current_index + 1].hash
                    proof.append((sibling_hash, 'right'))
                else:
                    # 没有右兄弟，使用自身
                    sibling_hash = level_nodes[current_index].hash
                    proof.append((sibling_hash, 'right'))
            else:
                # 当前节点是右子节点，需要左兄弟节点
                sibling_hash = level_nodes[current_index - 1].hash
                proof.append((sibling_hash, 'left'))
            
            current_index = current_index // 2
        
        return proof
    
    def verify_inclusion_proof(self, leaf_data: str, leaf_index: int, 
                             proof: List[Tuple[str, str]], root_hash: str) -> bool:
        """验证存在性证明"""
        current_hash = self.compute_leaf_hash(leaf_data)
        
        for sibling_hash, direction in proof:
            if direction == 'left':
                current_hash = self.compute_internal_hash(sibling_hash, current_hash)
            else:
                current_hash = self.compute_internal_hash(current_hash, sibling_hash)
        
        return current_hash == root_hash
    
    def get_non_inclusion_proof(self, target_data: str) -> Dict:
        """生成不存在性证明"""
        target_hash = self.compute_leaf_hash(target_data)
        
        # 查找目标哈希在已排序叶子中的位置
        leaf_hashes = [leaf.hash for leaf in self.leaves]
        leaf_hashes_sorted = sorted(leaf_hashes)
        
        # 如果目标已存在，则不能证明不存在
        if target_hash in leaf_hashes_sorted:
            return {
                'exists': True,
                'proof': None,
                'message': f"数据 '{target_data}' 已存在于树中"
            }
        
        # 找到相邻的两个叶子节点
        insert_pos = 0
        for i, leaf_hash in enumerate(leaf_hashes_sorted):
            if target_hash < leaf_hash:
                insert_pos = i
                break
            insert_pos = i + 1
        
        # 获取相邻节点的索引和证明
        left_index = max(0, insert_pos - 1)
        right_index = min(len(leaf_hashes_sorted) - 1, insert_pos)
        
        # 在原始列表中找到对应的索引
        left_original_index = leaf_hashes.index(leaf_hashes_sorted[left_index])
        right_original_index = leaf_hashes.index(leaf_hashes_sorted[right_index])
        
        left_proof = self.get_inclusion_proof(left_original_index)
        right_proof = self.get_inclusion_proof(right_original_index)
        
        return {
            'exists': False,
            'proof': {
                'target_hash': target_hash,
                'left_neighbor': {
                    'data': self.leaves[left_original_index].data,
                    'hash': leaf_hashes_sorted[left_index],
                    'proof': left_proof,
                    'index': left_original_index
                },
                'right_neighbor': {
                    'data': self.leaves[right_original_index].data,
                    'hash': leaf_hashes_sorted[right_index],
                    'proof': right_proof,
                    'index': right_original_index
                }
            },
            'message': f"数据 '{target_data}' 不存在于树中"
        }
    
    def verify_non_inclusion_proof(self, target_data: str, proof_data: Dict, root_hash: str) -> bool:
        """验证不存在性证明"""
        if proof_data.get('exists', False):
            return False
        
        proof = proof_data['proof']
        target_hash = self.compute_leaf_hash(target_data)
        
        # 验证相邻节点的存在性证明
        left_neighbor = proof['left_neighbor']
        right_neighbor = proof['right_neighbor']
        
        left_valid = self.verify_inclusion_proof(
            left_neighbor['data'], 
            left_neighbor['index'],
            left_neighbor['proof'], 
            root_hash
        )
        
        right_valid = self.verify_inclusion_proof(
            right_neighbor['data'],
            right_neighbor['index'], 
            right_neighbor['proof'],
            root_hash
        )
        
        # 验证目标哈希确实在两个相邻节点之间
        left_hash = left_neighbor['hash']
        right_hash = right_neighbor['hash']
        
        hash_in_range = left_hash < target_hash < right_hash or \
                       (left_hash == right_hash and target_hash != left_hash)
        
        return left_valid and right_valid and hash_in_range
    
    def get_tree_stats(self) -> Dict:
        """获取树的统计信息"""
        if not self.root:
            return {}
        
        def count_nodes(node):
            if not node:
                return 0
            return 1 + count_nodes(node.left) + count_nodes(node.right)
        
        total_nodes = count_nodes(self.root)
        height = len(self.tree_levels)
        
        return {
            'total_nodes': total_nodes,
            'leaf_count': self.leaf_count,
            'height': height,
            'root_hash': self.root.hash[:16] + '...',
            'levels': len(self.tree_levels)
        }
    
    def print_tree_stats(self):
        """打印树的统计信息"""
        stats = self.get_tree_stats()
        if not stats:
            print("树尚未构建")
            return
        
        print(f"\n=== Merkle树统计信息 ===")
        print(f"总节点数: {stats['total_nodes']}")
        print(f"叶子节点数: {stats['leaf_count']}")
        print(f"树高度: {stats['height']}")
        print(f"根哈希: {stats['root_hash']}")
        print(f"层数: {stats['levels']}")


def demo_merkle_tree():
    """Merkle树演示"""
    print("=== Merkle树演示 ===")
    
    # 创建测试数据
    leaf_data = [f"data_{i}" for i in range(10)]
    
    # 构建树
    tree = MerkleTree()
    root_hash = tree.build_tree(leaf_data)
    tree.print_tree_stats()
    
    print(f"\n根哈希: {root_hash}")
    
    # 测试存在性证明
    print(f"\n=== 存在性证明测试 ===")
    test_index = 3
    test_data = leaf_data[test_index]
    
    proof = tree.get_inclusion_proof(test_index)
    print(f"为数据 '{test_data}' (索引 {test_index}) 生成存在性证明")
    print(f"证明长度: {len(proof)}")
    
    # 验证存在性证明
    is_valid = tree.verify_inclusion_proof(test_data, test_index, proof, root_hash)
    print(f"存在性证明验证: {'通过' if is_valid else '失败'}")
    
    # 测试不存在性证明
    print(f"\n=== 不存在性证明测试 ===")
    non_existent_data = "non_existent_data"
    
    non_inclusion_proof = tree.get_non_inclusion_proof(non_existent_data)
    print(non_inclusion_proof['message'])
    
    if not non_inclusion_proof['exists']:
        # 验证不存在性证明
        is_valid = tree.verify_non_inclusion_proof(non_existent_data, non_inclusion_proof, root_hash)
        print(f"不存在性证明验证: {'通过' if is_valid else '失败'}")


def large_merkle_tree_test():
    """大规模Merkle树测试（10万节点）"""
    print(f"\n=== 大规模Merkle树测试 (100,000节点) ===")
    
    import time
    
    # 生成10万个测试数据
    print("生成测试数据...")
    large_data = [f"document_{i}_{hash(f'content_{i}')}" for i in range(100000)]
    
    # 构建树
    tree = MerkleTree()
    
    print("开始构建Merkle树...")
    start_time = time.time()
    root_hash = tree.build_tree(large_data)
    build_time = time.time() - start_time
    
    tree.print_tree_stats()
    print(f"构建时间: {build_time:.2f} 秒")
    
    # 测试存在性证明性能
    print(f"\n=== 性能测试 ===")
    test_indices = [0, 12345, 50000, 87654, 99999]
    
    for idx in test_indices:
        start_time = time.time()
        proof = tree.get_inclusion_proof(idx)
        proof_time = time.time() - start_time
        
        start_time = time.time()
        is_valid = tree.verify_inclusion_proof(large_data[idx], idx, proof, root_hash)
        verify_time = time.time() - start_time
        
        print(f"索引 {idx}: 证明生成 {proof_time*1000:.2f}ms, 验证 {verify_time*1000:.2f}ms, 有效: {is_valid}")


if __name__ == "__main__":
    # 运行小规模演示
    demo_merkle_tree()
    
    # 运行大规模测试
    large_merkle_tree_test()
