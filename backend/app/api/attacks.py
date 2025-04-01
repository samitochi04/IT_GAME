from flask import Blueprint, jsonify
from app.models.attack import Attack

bp = Blueprint('attacks', __name__)

@bp.route('/api/attacks/latest', methods=['GET'])
def get_latest_attacks():
    attack = Attack.query.order_by(Attack.timestamp.desc()).first()
    if attack:
        return jsonify({
            'id': attack.id,
            'timestamp': attack.timestamp,
            'category': attack.category,
            'technique_id': attack.technique_id,
            'description': attack.description,
            'indicators': attack.indicators
        })
    return jsonify({'message': 'No attacks found'}), 404
